//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//
//
// Bulbasaur: bulbasaur-cov-fast.so.cc  --  Fast Branch Coverage Pass
// ==================================================================
//
// A performance-optimised variant of the Full pass designed for the
// normal fuzzing inner loop. It applies edge pruning so that fewer basic
// blocks are instrumented, trading complete branch visibility for speed.
//
// Role in the pipeline:
//   - The default pass used during high-throughput fuzzing
//     (BULBASAUR_INST_MODE=FAST).
//   - When this pass detects a *new edge* it triggers a re-execution of
//     the same input under the Full pass to record fine-grained branch
//     information without slowing down the common case.
//
// How it differs from the Full pass (bulbasaur-cov-full.so):
//   - NoPrune=false: standard AFL++ dominator-tree edge pruning is applied,
//     reducing the number of instrumented blocks and keeping the bitmap small.
//   - Uses shouldInstrumentBlockNoPrune() for branch-trace target selection
//     (covers all blocks) but shouldInstrumentBlock() for sancov counter
//     placement (pruned set), so branch traces fire everywhere while AFL++
//     bitmap overhead stays minimal.
//   - The edge→branch section mappings are still emitted so the runtime can
//     translate a new-edge notification into the matching Full-pass branch ID.
//
// Env vars: same as bulbasaur-cov-full.so (AFL_DEBUG, AFL_QUIET, etc.)
//
// Built as: bulbasaur-cov-fast.so   (loaded via -fpass-plugin=)
// Plugin ID: "BulbasaurCovFast"
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#if LLVM_VERSION_MAJOR >= 15
  #if LLVM_VERSION_MAJOR < 17
    #include "llvm/ADT/Triple.h"
  #endif
#endif
#include "llvm/Analysis/PostDominators.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/CFG.h"
#endif
#include "llvm/IR/Constant.h"
#include "llvm/Analysis/ValueTracking.h"
#if LLVM_VERSION_MAJOR >= 20
  #include "llvm/IR/Constants.h"
  #include "llvm/IR/ValueSymbolTable.h"
#endif
#include "llvm/IR/DataLayout.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/DebugInfo.h"
#endif
#include "llvm/IR/Dominators.h"
#if LLVM_VERSION_MAJOR >= 17
  #include "llvm/IR/EHPersonalities.h"
#else
  #include "llvm/Analysis/EHPersonalities.h"
#endif
#include "llvm/IR/Function.h"
#if LLVM_VERSION_MAJOR >= 16
  #include "llvm/IR/GlobalVariable.h"
#endif
#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/InlineAsm.h"
#endif
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/MDBuilder.h"
  #include "llvm/IR/Mangler.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Type.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/InitializePasses.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/Support/raw_ostream.h"
#endif
#if LLVM_VERSION_MAJOR < 20
  #if LLVM_VERSION_MAJOR < 17
    #include "llvm/Transforms/Instrumentation.h"
  #else
    #include "llvm/TargetParser/Triple.h"
  #endif
#else
  #include "llvm/Transforms/Utils/Instrumentation.h"
#endif

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "sancov"

// Branch type tags stored in the branch_type ELF section.
// The runtime uses these to dispatch to the correct trace handler.
enum BranchType {
  Cmp = 1,           // ICmp whose result feeds a conditional branch
  ConstCmp,          // ICmp with one constant operand
  Switch,            // SwitchInst
  FCmp,              // FCmp (floating-point comparison)
  Strcmp,            // strcmp / strncmp / memcmp call → conditional branch
  ConstStrcmp,       // strcmp-family call with a constant string argument
  StrcmpNonTerm,     // strcmp-family call NOT directly feeding a branch
  ConstStrcmpNonTerm,
  RtnFunction,       // Pointer-returning comparison function
};

static const uint64_t SanCtorAndDtorPriority = 2;

const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
const char SanCovTraceCmp1[] = "__sanitizer_cov_trace_cmp1";
const char SanCovTraceCmp2[] = "__sanitizer_cov_trace_cmp2";
const char SanCovTraceCmp4[] = "__sanitizer_cov_trace_cmp4";
const char SanCovTraceCmp8[] = "__sanitizer_cov_trace_cmp8";
const char SanCovTraceConstCmp1[] = "__sanitizer_cov_trace_const_cmp1";
const char SanCovTraceConstCmp2[] = "__sanitizer_cov_trace_const_cmp2";
const char SanCovTraceConstCmp4[] = "__sanitizer_cov_trace_const_cmp4";
const char SanCovTraceConstCmp8[] = "__sanitizer_cov_trace_const_cmp8";
const char SanCovTraceSwitchName[] = "__sanitizer_cov_trace_switch";

const char log_br8[] = "log_br8";
const char log_br16[] = "log_br16";
const char log_br32[] = "log_br32";
const char log_br64[] = "log_br64";

const char strcmp_log[] = "strcmp_log";
const char strncmp_log[] = "strncmp_log";
const char memcmp_log[] = "memcmp_log";
const char strstr_log[] = "strstr_log";
const char ptr_rtn_log[] = "ptr_rtn_log";
const char ptr_rtn_gcc_stdstring_stdstring_log[] = "ptr_rtn_gcc_stdstring_stdstring_log";
const char ptr_rtn_gcc_stdstring_cstring_log[] = "ptr_rtn_gcc_stdstring_cstring_log";
const char ptr_rtn_llvm_stdstring_stdstring_log[] = "ptr_rtn_llvm_stdstring_stdstring_log";
const char ptr_rtn_llvm_stdstring_cstring_log[] = "ptr_rtn_llvm_stdstring_cstring_log";
const char non_term_strcmp_log[] = "non_term_strcmp_log";
const char non_term_strncmp_log[] = "non_term_strncmp_log";
const char non_term_memcmp_log[] = "non_term_memcmp_log";
const char non_term_strstr_log[] = "non_term_strstr_log";
const char non_term_ptr_rtn_log[] = "non_term_ptr_rtn_log";
const char non_term_ptr_rtn_gcc_stdstring_stdstring_log[] = "non_term_ptr_rtn_gcc_stdstring_stdstring_log";
const char non_term_ptr_rtn_gcc_stdstring_cstring_log[] = "non_term_ptr_rtn_gcc_stdstring_cstring_log";
const char non_term_ptr_rtn_llvm_stdstring_stdstring_log[] = "non_term_ptr_rtn_llvm_stdstring_stdstring_log";
const char non_term_ptr_rtn_llvm_stdstring_cstring_log[] = "non_term_ptr_rtn_llvm_stdstring_cstring_log";

const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char BranchGuardsSectionName[] = "branch_guards";
const char BranchTypeSectionName[] = "branch_type";
const char EdgeToPredBranchSectionName[] = "edge_to_pred_branch";

const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;
  // Options.NoPrune = true;
  Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class BulbasaurCoverageFastPass
    : public PassInfoMixin<BulbasaurCoverageFastPass> {

 public:
  BulbasaurCoverageFastPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  bool              instrumentModule(Module &M, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);

 private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void InjectTraceForSwitch(Function               &F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks, DenseMap<BasicBlock *, size_t> &BBMapIndex,
                      bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 uint32_t special);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx, bool IsLeafFunc = true);

  Function *CreateInitCallsForSections(
                                  Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
                                  const char *Section, const char *BranchSection, const char *BranchTypeSectionName,
                                  const char *EdgeToPredBranchSectionName);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  // Bulbasaur addition.
  void TraceCmpBranch(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void TraceStrcmpBranch(Function &F, ArrayRef<Instruction *> StrcmpTraceTargets);
  void TraceNonTermStrcmp(Function &F, ArrayRef<Instruction *> StrcmpTraceTargetsNonTerminator);
  void TraceSwitchBranch(Function &F, ArrayRef<Instruction *> SwitchTraceTargets, 
                                ArrayRef<ConstantInt *> case_val_list, std::vector<int> int_val_list);
  bool IsInterestingFunctionCall(CallInst *callInst, u8 favor_std, u8 favor_ptr_rtn);
  bool isSigned(Value *V0, Value *V1);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_VERSION_MAJOR >= 19
    I->setNoSanitizeMetadata();
#elif LLVM_VERSION_MAJOR >= 16
    I->setMetadata(LLVMContext::MD_nosanitize, MDNode::get(*C, std::nullopt));
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  std::string     getSectionName(const std::string &Section) const;
  std::string     getSectionStart(const std::string &Section) const;
  std::string     getSectionEnd(const std::string &Section) const;
  FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee  SanCovTraceCmpFunction[4];
  FunctionCallee  SanCovTraceConstCmpFunction[4];
  FunctionCallee  SanCovTraceSwitchFunction;

  FunctionCallee  BranchTraceCmpFunction[4];
  FunctionCallee  BranchTraceStrcmpFunction[9];
  FunctionCallee  BranchTraceNonTermStrcmpFunction[9];

  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy, *PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  uint32_t        instr = 0, selects = 0, unhandled = 0, dump_cc = 0;
  uint32_t        branches = 0, strcmp_cnt = 0, strncmp_cnt = 0, memcmp_cnt = 0, llvmstdc_cnt = 0, llvmstdstd_cnt = 0;
  uint32_t        calls_cnt = 0, gccstdstd_cnt = 0, gccstdc_cnt = 0, strstr_cnt = 0;
  GlobalVariable *AFLMapPtr = NULL;
  ConstantInt    *One = NULL;
  ConstantInt    *Zero = NULL;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "BulbasaurCovFast", "v1.0",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR == 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
  #if LLVM_VERSION_MAJOR >= 20
            PB.registerPipelineStartEPCallback(
  #else
            PB.registerOptimizerEarlyEPCallback(
  #endif
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(BulbasaurCoverageFastPass());

                });

          }};

}

PreservedAnalyses BulbasaurCoverageFastPass::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  BulbasaurCoverageFastPass ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  // TODO: Support LTO or llvm classic?
  // Note we still need afl-compiler-rt so we just disable the instrumentation
  // here.
  if (!getenv("AFL_SAN_NO_INST")) {

    if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
      return PreservedAnalyses::none();

  } else {

    if (getenv("AFL_DEBUG")) { DEBUGF("Instrument disabled\n"); }

  }

  return PreservedAnalyses::all();

}

std::pair<Value *, Value *> BulbasaurCoverageFastPass::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  // Use ExternalWeak so that if all sections are discarded due to section
  // garbage collection, the linker will not report undefined symbol errors.
  // Windows defines the start/stop symbols in compiler-rt so no need for
  // ExternalWeak.
  GlobalValue::LinkageTypes Linkage = TargetTriple.isOSBinFormatCOFF()
                                          ? GlobalVariable::ExternalLinkage
                                          : GlobalVariable::ExternalWeakLinkage;
  GlobalVariable *SecStart = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                                getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                              getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(SecStart, SecEnd);

    // Account for the fact that on windows-msvc __start_* symbols actually
    // point to a uint64_t before the start of the array.
#if LLVM_VERSION_MAJOR >= 19
  auto GEP =
      IRB.CreatePtrAdd(SecStart, ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(GEP, SecEnd);
#else
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, PointerType::getUnqual(Ty)),
                        SecEnd);
#endif

}

Function *BulbasaurCoverageFastPass::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section, const char *BranchSection, const char *BranchTypeSectionName,
    const char *EdgeToPredBranchSectionName) {

  auto      SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto      SecStart = SecStartEnd.first;
  auto      SecEnd = SecStartEnd.second;
  auto      BrSecStartEnd = CreateSecStartEnd(M, BranchSection, Ty);
  auto      BrSecStart = BrSecStartEnd.first;
  auto      BrSecEnd = BrSecStartEnd.second;
  auto      BranchTypeStartEnd = CreateSecStartEnd(M, BranchTypeSectionName, Ty);
  auto      EdgeToPredBranchStartEnd = CreateSecStartEnd(M, EdgeToPredBranchSectionName, Ty);

  Function *CtorFunc;
  Type     *PtrTy = PointerType::getUnqual(Ty);
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, 
      {PtrTy, PtrTy, PtrTy, PtrTy, PtrTy, PtrTy, PtrTy, PtrTy}, 
      {SecStart, SecEnd, BrSecStart, BrSecEnd, BranchTypeStartEnd.first, BranchTypeStartEnd.second, EdgeToPredBranchStartEnd.first, EdgeToPredBranchStartEnd.second});
  // assert(CtorFunc->getName() == CtorName);

  if (TargetTriple.supportsCOMDAT()) {

    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);

  } else {

    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);

  }

  if (TargetTriple.isOSBinFormatCOFF()) {

    // In COFF files, if the constructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);

  }

  return CtorFunc;

}

bool BulbasaurCoverageFastPass::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) { debug = 1; }

  if (getenv("AFL_DUMP_CYCLOMATIC_COMPLEXITY")) { dump_cc = 1; }

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "BulbasaurCov[Fast]" VERSION cRST "\n");

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  initInstrumentList();
  scanForDangerousFunctions(&M);

  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();
  PtrTy = PointerType::getUnqual(*C);

  LLVMContext &Ctx = M.getContext();
  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
  Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

  // Make sure smaller parameters are zero-extended to i64 if required by the
  // target ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  SanCovTraceCmpFunction[0] =
      M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt8Ty(), IRB.getInt8Ty());
  SanCovTraceCmpFunction[1] =
      M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt16Ty(), IRB.getInt16Ty());
  SanCovTraceCmpFunction[2] =
      M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt32Ty(), IRB.getInt32Ty());
  SanCovTraceCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(
      SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
  SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(
      SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
  SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(
      SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
  SanCovTraceConstCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceSwitchFunction =
      M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack || SanCovLowestStack->getValueType() != IntptrTy) {

    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    return true;

  }

  // Set Zero Extension for Branch Trace.
  AttributeList BranchTraceCmpZeroExtAL;
  BranchTraceCmpZeroExtAL =
      BranchTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  BranchTraceCmpZeroExtAL =
      BranchTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);
  BranchTraceCmpZeroExtAL =
      BranchTraceCmpZeroExtAL.addParamAttribute(*C, 2, Attribute::ZExt);

  // Instrument Functions Declaration, which implemented in afl-compiler-rt.
  BranchTraceCmpFunction[0] =
      M.getOrInsertFunction(log_br8, BranchTraceCmpZeroExtAL, VoidTy, Int32Ty,
                         Int8Ty, Int8Ty);
  BranchTraceCmpFunction[1] =
      M.getOrInsertFunction(log_br16, BranchTraceCmpZeroExtAL, VoidTy, Int32Ty,
                         Int16Ty, Int16Ty);
  BranchTraceCmpFunction[2] =
      M.getOrInsertFunction(log_br32, BranchTraceCmpZeroExtAL, VoidTy, Int32Ty,
                         Int32Ty, Int32Ty);
  BranchTraceCmpFunction[3] =
      M.getOrInsertFunction(log_br64, BranchTraceCmpZeroExtAL, VoidTy, Int32Ty, Int64Ty, Int64Ty);
  
  BranchTraceStrcmpFunction[0] =
      M.getOrInsertFunction(strcmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[1] =
      M.getOrInsertFunction(strncmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[2] =
      M.getOrInsertFunction(memcmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  // BranchTraceStrcmpFunction[3] =
  //     M.getOrInsertFunction(strstr_log, VoidTy,Int32Ty,
  //                        Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[4] =
      M.getOrInsertFunction(ptr_rtn_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[5] =
      M.getOrInsertFunction(ptr_rtn_gcc_stdstring_stdstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[6] =
      M.getOrInsertFunction(ptr_rtn_gcc_stdstring_cstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[7] =
      M.getOrInsertFunction(ptr_rtn_llvm_stdstring_stdstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceStrcmpFunction[8] =
      M.getOrInsertFunction(ptr_rtn_llvm_stdstring_cstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);

  
  BranchTraceNonTermStrcmpFunction[0] =
      M.getOrInsertFunction(non_term_strcmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[1] =
      M.getOrInsertFunction(non_term_strncmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[2] =
      M.getOrInsertFunction(non_term_memcmp_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  // BranchTraceNonTermStrcmpFunction[3] =
  //     M.getOrInsertFunction(non_term_strstr_log, VoidTy,Int32Ty,
  //                        Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[4] =
      M.getOrInsertFunction(non_term_ptr_rtn_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[5] =
      M.getOrInsertFunction(non_term_ptr_rtn_gcc_stdstring_stdstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[6] =
      M.getOrInsertFunction(non_term_ptr_rtn_gcc_stdstring_cstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[7] =
      M.getOrInsertFunction(non_term_ptr_rtn_llvm_stdstring_stdstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);
  BranchTraceNonTermStrcmpFunction[8] =
      M.getOrInsertFunction(non_term_ptr_rtn_llvm_stdstring_cstring_log, VoidTy,Int32Ty,
                         Int8PtrTy, Int8PtrTy, Int64Ty);


  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
  SanCovTracePCGuard =
      M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  Function *Ctor = nullptr;

  if (FunctionGuardArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                      SanCovTracePCGuardInitName, Int32PtrTy,
                                      SanCovGuardsSectionName, BranchGuardsSectionName, 
                                      BranchTypeSectionName, EdgeToPredBranchSectionName);

  if (Ctor && debug) {

    fprintf(stderr, "SANCOV: installed pcguard_init in ctor\n");

  }

  appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

  if (!be_quiet) {

    if (!instr) {

      WARNF("No instrumentation targets found.");

    } else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("[SanitizerCoveragePCGUARDFast] Instrumented %u locations with no collisions (%s mode) of which are "
          "%u handled and %u unhandled selects.",
          instr, modeline, selects, unhandled);
      OKF("[SanitizerCoveragePCGUARDFast] Instrumented %u valid branches, calls cnt %u, gccstdstd cnt %u, "
          "gccstdc cnt %u, llvmstdstd cnt %u, llvmstdc cnt %u, strcmp %u, strncmp %u, memcmp %u, strstr %u", 
          branches, calls_cnt, gccstdstd_cnt, gccstdc_cnt, llvmstdstd_cnt, llvmstdc_cnt, strcmp_cnt, strncmp_cnt, memcmp_cnt, strstr_cnt);

    }

  }

  return true;

}

static bool isConstantStr(Value* V) {
  std::string Str;
  StringRef   TmpStr;
  getConstantStringInfo(V, TmpStr);
  if(TmpStr.empty()){
    auto *Ptr = dyn_cast<ConstantExpr>(V);
    if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {
      if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {
        if (Var->hasInitializer()) {
          if (auto *Array = dyn_cast<ConstantDataArray>(Var->getInitializer())) {
            TmpStr = Array->getRawDataValues();
          }
        }
      }
    }
  }

  if (TmpStr.empty()) {
    return false;
  } else {
    return true;
  }
}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_empty(BB)) return false;

  return llvm::all_of(successors(BB), [&](const BasicBlock *SUCC) {

    return DT->dominates(BB, SUCC);

  });

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_empty(BB)) return false;

  return llvm::all_of(predecessors(BB), [&](const BasicBlock *PRED) {

    return PDT->dominates(BB, PRED);

  });

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree            *DT,
                                  const PostDominatorTree        *PDT,
                                  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

static bool shouldInstrumentBlockNoPrune(const Function &F, const BasicBlock *BB,
  const DominatorTree            *DT,
  const PostDominatorTree        *PDT,
  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;
  return true;
}

// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
#if 0
static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {

  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;

}

#endif

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
#if 0
static bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                             const SanitizerCoverageOptions &Options) {

  if (!Options.NoPrune)
    if (CMP->hasOneUse())
      if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
        for (BasicBlock *B : BR->successors())
          if (IsBackEdge(BR->getParent(), B, DT))
            return false;
  return true;

}

#endif

static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {

  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;

}

// We only hook integer comparisons
bool IsInterestingBranchCmp(CmpInst *CMP, const DominatorTree *DT,
                      const SanitizerCoverageOptions &Options, const DataLayout *DL) {
  Value *A0 = CMP->getOperand(0);
  Value *A1 = CMP->getOperand(1);
  Type *Ty = A0->getType();

  // Check integer comparisons
  if (Ty->isIntegerTy()) {
    unsigned TypeSize = cast<IntegerType>(Ty)->getBitWidth();
    if ((TypeSize != 8) && (TypeSize != 16) && (TypeSize != 32) && (TypeSize != 64))
      return false;
  } else {
    return false;
  }

  if (isa<ConstantInt>(A0) && isa<ConstantInt>(A1)) {
    return false;
  }

  return true;
}

bool BulbasaurCoverageFastPass::IsInterestingFunctionCall(CallInst *callInst, u8 favor_std, u8 favor_ptr_rtn) {
  Function *Callee = callInst->getCalledFunction();
  if (!Callee) return false;
  if (callInst->getCallingConv() != llvm::CallingConv::C) return false;

  FunctionType *FT = Callee->getFunctionType();
  std::string   FuncName = Callee->getName().str();

  if (FT->getNumParams() < 2) {
    return false;
  }

  Value *V0 = callInst->getArgOperand(0),
        *V1 = callInst->getArgOperand(1);

  if (isConstantStr(V0) && isConstantStr(V1)) {
    // llvm::outs() << "Both args are constant, skip it: " << *callInst << "\n";
    return false;
  }

  bool isPtrRtn = FT->getNumParams() >= 2 &&
                  !FT->getReturnType()->isVoidTy() &&
                  FT->getParamType(0) == FT->getParamType(1) &&
                  FT->getParamType(0)->isPointerTy();

  bool isPtrRtnN = FT->getNumParams() >= 3 &&
                   !FT->getReturnType()->isVoidTy() &&
                   FT->getParamType(0) == FT->getParamType(1) &&
                   FT->getParamType(0)->isPointerTy() &&
                   FT->getParamType(2)->isIntegerTy();
  if (isPtrRtnN) {

    auto intTyOp =
        dyn_cast<IntegerType>(callInst->getArgOperand(2)->getType());
    if (intTyOp) {

      if (intTyOp->getBitWidth() != 32 &&
        intTyOp->getBitWidth() != 64) {

        isPtrRtnN = false;

      }

    }

  }

  bool isMemcmp =
      (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
       !FuncName.compare("CRYPTO_memcmp") ||
       !FuncName.compare("OPENSSL_memcmp") ||
       !FuncName.compare("memcmp_const_time") ||
       !FuncName.compare("memcmpct"));
  isMemcmp &= FT->getNumParams() == 3 &&
              FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy() &&
              FT->getParamType(2)->isIntegerTy();

  bool isStrcmp =
      (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
       !FuncName.compare("xmlStrEqual") ||
       !FuncName.compare("g_strcmp0") ||
       !FuncName.compare("curl_strequal") ||
       !FuncName.compare("strcsequal") ||
       !FuncName.compare("strcasecmp") ||
       !FuncName.compare("stricmp") ||
       !FuncName.compare("ap_cstr_casecmp") ||
       !FuncName.compare("OPENSSL_strcasecmp") ||
       !FuncName.compare("xmlStrcasecmp") ||
       !FuncName.compare("g_strcasecmp") ||
       !FuncName.compare("g_ascii_strcasecmp") ||
       !FuncName.compare("Curl_strcasecompare") ||
       !FuncName.compare("Curl_safe_strcasecompare") ||
       !FuncName.compare("cmsstrcasecmp") ||
       !FuncName.compare("strstr") ||
       !FuncName.compare("g_strstr_len") ||
       !FuncName.compare("ap_strcasestr") ||
       !FuncName.compare("xmlStrstr") ||
       !FuncName.compare("xmlStrcasestr") ||
       !FuncName.compare("g_str_has_prefix") ||
       !FuncName.compare("g_str_has_suffix"));
  isStrcmp &=
      FT->getNumParams() == 2 &&
      FT->getParamType(0) == FT->getParamType(1) &&
      FT->getParamType(0) ==
          IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0);

  bool isStrncmp = (!FuncName.compare("strncmp") ||
                    !FuncName.compare("xmlStrncmp") ||
                    !FuncName.compare("curl_strnequal") ||
                    !FuncName.compare("strncasecmp") ||
                    !FuncName.compare("strnicmp") ||
                    !FuncName.compare("ap_cstr_casecmpn") ||
                    !FuncName.compare("OPENSSL_strncasecmp") ||
                    !FuncName.compare("xmlStrncasecmp") ||
                    !FuncName.compare("g_ascii_strncasecmp") ||
                    !FuncName.compare("Curl_strncasecompare") ||
                    !FuncName.compare("g_strncasecmp"));
  isStrncmp &=
      FT->getNumParams() == 3 &&
      FT->getParamType(0) == FT->getParamType(1) &&
      FT->getParamType(0) ==
          IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0) &&
      FT->getParamType(2)->isIntegerTy();

  bool isGccStdStringStdString =
      Callee->getName().find("__is_charIT_EE7__value") !=
          std::string::npos &&
      Callee->getName().find(
          "St7__cxx1112basic_stringIS2_St11char_traits") !=
          std::string::npos &&
      FT->getNumParams() >= 2 &&
      FT->getParamType(0) == FT->getParamType(1) &&
      FT->getParamType(0)->isPointerTy();

  bool isGccStdStringCString =
      Callee->getName().find(
          "St7__cxx1112basic_stringIcSt11char_"
          "traitsIcESaIcEE7compareEPK") != std::string::npos &&
      FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
      FT->getParamType(1)->isPointerTy();

  bool isLlvmStdStringStdString =
      Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
      Callee->getName().find("_12basic_stringI") != std::string::npos &&
      Callee->getName().find("_11char_traits") != std::string::npos &&
      FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
      FT->getParamType(1)->isPointerTy();

  bool isLlvmStdStringCString =
      Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
      Callee->getName().find("_12basic_stringI") != std::string::npos &&
      FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
      FT->getParamType(1)->isPointerTy();

  if (isGccStdStringCString || isGccStdStringStdString ||
      isLlvmStdStringStdString || isLlvmStdStringCString || isMemcmp ||
      isStrcmp || isStrncmp) {

    isPtrRtnN = isPtrRtn = false;

  }

  if ( (favor_std && (isGccStdStringCString || isGccStdStringStdString || isLlvmStdStringStdString || isLlvmStdStringCString) ) || 
        isMemcmp || isStrcmp || isStrncmp || ( favor_ptr_rtn && (isPtrRtn || isPtrRtnN) ) ) {
      return true;
  }

  return false;

}

void BulbasaurCoverageFastPass::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (!isInInstrumentList(&F, FMNAME)) return;
  // if (F.getName().find(".module_ctor") != std::string::npos)
  if (F.getName().contains(".module_ctor"))
    return;  // Should not instrument sanitizer init functions.
#if LLVM_VERSION_MAJOR >= 18
  if (F.getName().starts_with("__sanitizer_"))
#else
  if (F.getName().startswith("__sanitizer_"))
#endif
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (F.hasFnAttribute(Attribute::NoSanitizeCoverage)) return;
#if LLVM_VERSION_MAJOR >= 19
  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) return;
#endif
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<BasicBlock *, 16>       BlocksToInstrument;
  SmallVector<Instruction *, 8>       CmpTraceTargets; // cmp
  
  // TODO: 
  SmallVector<Instruction *, 8>       CmpTraceTargetsNonTerminator; // cmp
  SmallVector<Instruction *, 8>       SancovForCmpNonTerminator;
  SmallVector<Instruction *, 8>       SelectInstArray; // select
  
  SmallVector<Instruction *, 8>       StrcmpTraceTargets; // strcmp
  
  SmallVector<Instruction *, 8>       StrcmpTraceTargetsNonTerminator;
  
  SmallVector<Instruction *, 8>       SwitchTraceTargets; // switch
  SmallVector<ConstantInt*, 128>      case_val_list;
  std::vector<int>                    int_val_list;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;

  // bb -> index of bb in array
  DenseMap<BasicBlock*, size_t> BBMapIndex;

  // Two-tier block selection:
  //   BlocksToFullInstrument – all blocks eligible for branch tracing (no pruning).
  //     Used so branch-trace targets cover every comparison site, even those
  //     that AFL++'s dominator pruning would normally skip.
  //   BlocksToInstrument     – pruned set for sancov counter placement.
  //     Keeps the AFL++ bitmap small; standard edge-pruning heuristics apply.
  DenseSet<BasicBlock*> BlocksToFullInstrument;

  for (auto &BB : F) {

    if (shouldInstrumentBlockNoPrune(F, &BB, DT, PDT, Options)) {
      BlocksToFullInstrument.insert(&BB);
    }

    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);
    /*
        for (auto &Inst : BB) {

          if (Options.TraceCmp) {

            if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst))
              if (IsInterestingCmp(CMP, DT, Options))
                CmpTraceTargets.push_back(&Inst);
            if (isa<SwitchInst>(&Inst))
              SwitchTraceTargets.push_back(&Inst);

          }

        }

    */

  }

  if (debug) {

    fprintf(stderr, "BulbasaurCov[Fast]: instrumenting %s in %s\n",
            F.getName().str().c_str(), F.getParent()->getName().str().c_str());

  }

  InjectCoverage(F, BlocksToInstrument, BBMapIndex, IsLeafFunc);
  // InjectTraceForCmp(F, CmpTraceTargets);
  // InjectTraceForSwitch(F, SwitchTraceTargets);
  for (auto &BB : F) {
    if (!shouldInstrumentBlockNoPrune(F, &BB, DT, PDT, Options)) {
      continue;
    }

    for (auto &Inst : BB) {
      if (CmpInst *CMP = dyn_cast<CmpInst>(&Inst)) {
        if (IsInterestingBranchCmp(CMP, DT, Options, DL)) {
          int found_cmp_terminator = 0;
          // 1. check CMP as branch condition
          if (auto* br_inst = dyn_cast<BranchInst>(BB.getTerminator())) {
            if (br_inst->isConditional()) {
              if (CmpInst* cmp_inst = dyn_cast<CmpInst> (br_inst->getCondition())) {
                if (cmp_inst == CMP) {
                  found_cmp_terminator = 1;
                  // if CMP is like CMP(strcmp(...), CONST), instrument strcmp instead of CMP
                  Value *A0 = CMP->getOperand(0);
                  Value *A1 = CMP->getOperand(1);
                  
                  bool FirstIsConst = isa<ConstantInt>(A0);
                  bool SecondIsConst = isa<ConstantInt>(A1);
                  bool instrumentStrcmp = 0;
                  if (!FirstIsConst && SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A0)) {

                      if (IsInterestingFunctionCall(callInst, 1, 0)) {
                        if (BlocksToFullInstrument.contains(&BB)) {
                          // We only instrument the branches whose source basic blocks are instrumented in full mode.
                          StrcmpTraceTargets.push_back(callInst);
                          instrumentStrcmp = 1;
                        } else {
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }

                    }
                  }
                  // rare case
                  else if (FirstIsConst && !SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A1)) {

                      if (IsInterestingFunctionCall(callInst, 1, 0)) {
                        if (BlocksToFullInstrument.contains(&BB)) {
                          // We only instrument the branches whose source basic blocks are instrumented in full mode.
                          StrcmpTraceTargets.push_back(callInst);
                          instrumentStrcmp = 1;
                        } else {
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }

                    }    
                  }

                  if (!instrumentStrcmp){

                    if (BlocksToFullInstrument.contains(&BB)) {
                      // We only instrument the branches whose source basic blocks are instrumented in full mode.
                      CmpTraceTargets.push_back(&Inst);
                    } else {
                      errs()<< "\n [BUG] cmp fails to find sancov\n";
                    }
                    
                  }
                }
              }
            }
          }
        }
      }

      if (SwitchInst* SI = dyn_cast<SwitchInst>(&Inst)) {
        Value* op1 = SI->getCondition();
        if (!op1->getType()->isIntegerTy()) continue;
        //uint64_t TypeSize = DL->getTypeStoreSizeInBits(op1->getType());
        unsigned TypeSize = (cast<IntegerType>(op1->getType()))->getBitWidth();
        if ((TypeSize != 8) && (TypeSize != 16) && (TypeSize != 32) && (TypeSize != 64)) continue;
        
        SwitchTraceTargets.push_back(&Inst);
        // find target sancov id for each case
        for (auto i = SI->case_begin(), e = SI->case_end(); i != e;++i) {
          ConstantInt* op2 = dyn_cast<ConstantInt>(i->getCaseValue());
          BasicBlock* targetBB = i->getCaseSuccessor();
          if (BlocksToFullInstrument.contains(targetBB)) {

            int_val_list.push_back(op2->getSExtValue());
            case_val_list.push_back(op2);
          } else {
            errs()<< "\n[BUG] switch fails to find target BB sancov 2\n";
          }
          
        }

        // find case value for default case
        std::vector<int> tmp_val_list;
        for (auto i = SI->case_begin(), e = SI->case_end(); i != e;++i) {
          ConstantInt* op2 = dyn_cast<ConstantInt>(i->getCaseValue());
          BasicBlock* targetBB = i->getCaseSuccessor();
          if (BlocksToFullInstrument.contains(targetBB)) {
            tmp_val_list.push_back(op2->getSExtValue());
          }
        }
	      if (tmp_val_list.empty()) {
            int_val_list.push_back(0);
            case_val_list.push_back(NULL);
            continue;
        }
        int max_int = *max_element(tmp_val_list.begin(), tmp_val_list.end());
        int min_int = *min_element(tmp_val_list.begin(), tmp_val_list.end());
        Value * de_val;
        int found_target_val = 0;
        for (int default_val = min_int; default_val < max_int; default_val ++ ){
          if (std::find(tmp_val_list.begin(), tmp_val_list.end(), default_val) == tmp_val_list.end()) {
            de_val = ConstantInt::get(op1->getType(), default_val);
            found_target_val = 1;
            break;
          }
        }
        if (!found_target_val)
          de_val = ConstantInt::get(op1->getType(), max_int + 1);

        BasicBlock* targetBB = SI->getDefaultDest();

        if (BlocksToFullInstrument.contains(targetBB)) {

          ConstantInt* op2 = dyn_cast<ConstantInt>(de_val);
          int_val_list.push_back(op2->getSExtValue());
          case_val_list.push_back(op2);

        } else {
          
          int_val_list.push_back(0);
          case_val_list.push_back(NULL);
          
          SI->print(errs());
          errs()<< "\n[LOG] skipped the dead default switch case\n";
        }

        
      }
    }
  }

  for (auto &BB : F) {
    if (!BlocksToFullInstrument.contains(&BB)) {
      continue;
    }

    for (auto &Inst : BB) {
      // Check bb again to get non-term strcmp instructions.
      if (isa<CallInst>(&Inst)) {
        CallInst* callInst = dyn_cast<CallInst>(&Inst);

        if (IsInterestingFunctionCall(callInst, 1, 0)) {
          bool found_item = 0;
          for (auto tmpI : StrcmpTraceTargets) {
            if (tmpI == callInst){
              found_item = 1;
              break;
            }
          }
          // case 2: Strcmp not used in terminator condition
          if (!found_item) {

            StrcmpTraceTargetsNonTerminator.push_back(callInst);

          }
        }
      }
    }
  }

  // TODO: handle with select instruction.
  
  // cmp
  TraceCmpBranch(F, CmpTraceTargets);
  // strcmp
  TraceStrcmpBranch(F, StrcmpTraceTargets);
  // non-term strcmp
  TraceNonTermStrcmp(F, StrcmpTraceTargetsNonTerminator);
  // switch
  TraceSwitchBranch(F, SwitchTraceTargets, 
                    case_val_list, int_val_list);

  if (dump_cc) { calcCyclomaticComplexity(&F); }

}

GlobalVariable *BulbasaurCoverageFastPass::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
  Array->setSection(getSectionName(Section));
#if LLVM_VERSION_MAJOR >= 16
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
#else
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#endif

  // sancov_pcs parallels the other metadata section(s). Optimizers (e.g.
  // GlobalOpt/ConstantMerge) may not discard sancov_pcs and the other
  // section(s) as a unit, so we conservatively retain all unconditionally in
  // the compiler.
  //
  // With comdat (COFF/ELF), the linker can guarantee the associated sections
  // will be retained or discarded as a unit, so llvm.compiler.used is
  // sufficient. Otherwise, conservatively make all of them retained by the
  // linker.
  if (Array->hasComdat())
    GlobalsToAppendToCompilerUsed.push_back(Array);
  else
    GlobalsToAppendToUsed.push_back(Array);

  return Array;

}

GlobalVariable *BulbasaurCoverageFastPass::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, PtrTy));
      PCs.push_back(
          (Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 1), PtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), PtrTy));
#if LLVM_VERSION_MAJOR >= 16
      PCs.push_back(Constant::getNullValue(PtrTy));
#else
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));
#endif

    }

  }

  auto *PCArray =
      CreateFunctionLocalArrayInSection(N * 2, F, PtrTy, SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(PtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void BulbasaurCoverageFastPass::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);

}

bool BulbasaurCoverageFastPass::InjectCoverage(
  Function &F, ArrayRef<BasicBlock *> AllBlocks, DenseMap<BasicBlock*, size_t> &BBMapIndex, bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;

  uint32_t        cnt_cov = 0, cnt_sel = 0, cnt_sel_inc = 0;
  static uint32_t first = 1;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (!FuncName.compare(StringRef("__afl_coverage_interesting"))) {

          cnt_cov++;

        }

      }

      SelectInst *selectInst = nullptr;

      if ((selectInst = dyn_cast<SelectInst>(&IN))) {

        Value *c = selectInst->getCondition();
        auto   t = c->getType();
        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          cnt_sel++;
          cnt_sel_inc += 2;

        }

        else if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            cnt_sel++;
            cnt_sel_inc += (tt->getElementCount().getKnownMinValue() * 2);

          }

        }

      }

    }

  }

  CreateFunctionLocalArrays(F, AllBlocks, first + cnt_cov + cnt_sel_inc);

  if (first) { first = 0; }
  selects += cnt_sel;

  uint32_t special = 0, local_selects = 0, skip_next = 0;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

#if LLVM_VERSION_MAJOR >= 20
        // test canary
        InstrumentationIRBuilder IRB(callInst);
#else
        IRBuilder<> IRB(callInst);
#endif

        if (!FunctionGuardArray) {

          fprintf(stderr,
                  "SANCOV: FunctionGuardArray is NULL, failed to emit "
                  "instrumentation.");
          continue;

        }

        Value *GuardPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(
                IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                ConstantInt::get(IntptrTy, (++special + AllBlocks.size()) * 4)),
            Int32PtrTy);

        LoadInst *Idx = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
        BulbasaurCoverageFastPass::SetNoSanitizeMetadata(Idx);

        callInst->setOperand(1, Idx);

      }

      SelectInst *selectInst = nullptr;

      if (!skip_next && (selectInst = dyn_cast<SelectInst>(&IN))) {

        uint32_t    vector_cnt = 0;
        Value      *condition = selectInst->getCondition();
        Value      *result;
        auto        t = condition->getType();
        IRBuilder<> IRB(selectInst->getNextNode());

        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          if (!FunctionGuardArray) {

            fprintf(stderr,
                    "SANCOV: FunctionGuardArray is NULL, failed to emit "
                    "instrumentation.");
            continue;

          }

          auto GuardPtr1 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          auto GuardPtr2 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          result = IRB.CreateSelect(condition, GuardPtr1, GuardPtr2);

        } else

#if LLVM_VERSION_MAJOR >= 14
            if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            uint32_t elements = tt->getElementCount().getFixedValue();
            vector_cnt = elements;
            if (elements) {

              FixedVectorType *GuardPtr1 =
                  FixedVectorType::get(Int32PtrTy, elements);
              FixedVectorType *GuardPtr2 =
                  FixedVectorType::get(Int32PtrTy, elements);
              Value *x, *y;

              if (!FunctionGuardArray) {

                fprintf(stderr,
                        "SANCOV: FunctionGuardArray is NULL, failed to emit "
                        "instrumentation.");
                continue;

              }

              Value *val1 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);

              Value *val2 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

              for (uint64_t i = 1; i < elements; i++) {

                val1 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                x = IRB.CreateInsertElement(x, val1, i);

                val2 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                y = IRB.CreateInsertElement(y, val2, i);

              }

              result = IRB.CreateSelect(condition, x, y);

            }

          }

        } else

#endif
        {

          // fprintf(stderr, "UNHANDLED: %u\n", t->getTypeID());
          unhandled++;
          continue;

        }

        uint32_t vector_cur = 0;

        /* Load SHM pointer */

        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
        BulbasaurCoverageFastPass::SetNoSanitizeMetadata(MapPtr);

        while (1) {

          /* Get CurLoc */
          LoadInst *CurLoc = nullptr;
          Value    *MapPtrIdx = nullptr;

          /* Load counter for CurLoc */
          if (!vector_cnt) {

            CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), result);
            BulbasaurCoverageFastPass::SetNoSanitizeMetadata(CurLoc);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

          } else {

            auto element = IRB.CreateExtractElement(result, vector_cur++);
            auto elementptr = IRB.CreateIntToPtr(element, Int32PtrTy);
            auto elementld = IRB.CreateLoad(IRB.getInt32Ty(), elementptr);
            BulbasaurCoverageFastPass::SetNoSanitizeMetadata(elementld);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, elementld);

          }

          if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

          } else {

            LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
            BulbasaurCoverageFastPass::SetNoSanitizeMetadata(Counter);

            /* Update bitmap */

            Value *Incr = IRB.CreateAdd(Counter, One);

            if (skip_nozero == NULL) {

              auto cf = IRB.CreateICmpEQ(Incr, Zero);
              auto carry = IRB.CreateZExt(cf, Int8Ty);
              Incr = IRB.CreateAdd(Incr, carry);

            }

            StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
            BulbasaurCoverageFastPass::SetNoSanitizeMetadata(StoreCtx);

          }

          if (!vector_cnt) {

            vector_cnt = 2;
            break;

          } else if (vector_cnt == vector_cur) {

            break;

          }

        }

        skip_next = 1;
        instr += vector_cnt;

      } else {

        skip_next = 0;

      }

    }

  }

  if (AllBlocks.empty() && !special && !local_selects) return false;

  if (!AllBlocks.empty())
    for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {
      BBMapIndex[AllBlocks[i]] = i;
      InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);
    }
  return true;

}

// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void BulbasaurCoverageFastPass::InjectTraceForSwitch(
    Function &, ArrayRef<Instruction *> SwitchTraceTargets) {

  for (auto I : SwitchTraceTargets) {

    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      IRBuilder<>                 IRB(I);
      SmallVector<Constant *, 16> Initializers;
      Value                      *Cond = SI->getCondition();
      if (Cond->getType()->getScalarSizeInBits() >
          Int64Ty->getScalarSizeInBits())
        continue;
      Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
      Initializers.push_back(
          ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
      if (Cond->getType()->getScalarSizeInBits() <
          Int64Ty->getScalarSizeInBits())
        Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
      for (auto It : SI->cases()) {

        Constant *C = It.getCaseValue();
        if (C->getType()->getScalarSizeInBits() <
            Int64Ty->getScalarSizeInBits())
          C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
        Initializers.push_back(C);

      }

      llvm::sort(drop_begin(Initializers, 2),
                 [](const Constant *A, const Constant *B) {

                   return cast<ConstantInt>(A)->getLimitedValue() <
                          cast<ConstantInt>(B)->getLimitedValue();

                 });

      ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
      GlobalVariable *GV = new GlobalVariable(
          *CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
          ConstantArray::get(ArrayOfInt64Ty, Initializers),
          "__sancov_gen_cov_switch_values");
      IRB.CreateCall(SanCovTraceSwitchFunction,
                     {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});

    }

  }

}

void BulbasaurCoverageFastPass::InjectTraceForCmp(
    Function &, ArrayRef<Instruction *> CmpTraceTargets) {

  for (auto I : CmpTraceTargets) {

    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {

      IRBuilder<> IRB(ICMP);
      Value      *A0 = ICMP->getOperand(0);
      Value      *A1 = ICMP->getOperand(1);
      if (!A0->getType()->isIntegerTy()) continue;
      uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      // If only one is const, then make it the first callback argument.
      if (FirstIsConst || SecondIsConst) {

        CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
        if (SecondIsConst) std::swap(A0, A1);

      }

      auto Ty = Type::getIntNTy(*C, TypeSize);
      IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
                                    IRB.CreateIntCast(A1, Ty, true)});

    }

  }

}

void BulbasaurCoverageFastPass::InjectCoverageAtBlock(Function   &F,
                                                       BasicBlock &BB,
                                                       size_t      Idx,
                                                       bool        IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();
  DebugLoc             EntryLoc;

  if (IsEntryBB) {

    if (auto SP = F.getSubprogram())
      EntryLoc = DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
#if LLVM_VERSION_MAJOR < 15

  } else {

    EntryLoc = IP->getDebugLoc();
    if (!EntryLoc)
      if (auto *SP = F.getSubprogram())
        EntryLoc = DILocation::get(SP->getContext(), 0, 0, SP);
#endif

  }

#if LLVM_VERSION_MAJOR >= 16
  InstrumentationIRBuilder IRB(&*IP);
#else
  IRBuilder<> IRB(&*IP);
#endif
  if (EntryLoc) IRB.SetCurrentDebugLocation(EntryLoc);
  if (Options.TracePCGuard) {

    /*
      auto GuardPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, Idx * 4)),
          Int32PtrTy);
      IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    */

    /* Get CurLoc */

    Value *GuardPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(IntptrTy, Idx * 4)),
        Int32PtrTy);

    LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
    BulbasaurCoverageFastPass::SetNoSanitizeMetadata(CurLoc);

    /* Load SHM pointer */

    LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    BulbasaurCoverageFastPass::SetNoSanitizeMetadata(MapPtr);

    /* Load counter for CurLoc */

    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

    if (use_threadsafe_counters) {

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      BulbasaurCoverageFastPass::SetNoSanitizeMetadata(Counter);

      /* Update bitmap */

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
      BulbasaurCoverageFastPass::SetNoSanitizeMetadata(StoreCtx);

    }

    // done :)

    //    IRB.CreateCall(SanCovTracePCGuard, Offset)->setCannotMerge();
    //    IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    ++instr;

  }

}

std::string BulbasaurCoverageFastPass::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    if (Section == SanCovCountersSectionName) return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
    if (Section == SanCovPCsSectionName) return ".SCOVP$M";
    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

std::string BulbasaurCoverageFastPass::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string BulbasaurCoverageFastPass::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

bool BulbasaurCoverageFastPass::isSigned(Value *V0, Value *V1) {
  if (isa<SExtInst>(V0) || isa<SExtInst>(V1)) {
      return true;
  }
  if (isa<ZExtInst>(V0) || isa<ZExtInst>(V1)) {
      return false;
  }
  // if (debug) {
  //   fprintf(stderr, "[Warning] Unable to determine signedness:\n");
  //   V0 ? V0->print(errs()) : errs() << "  V0: (null)\n";
  //   V1 ? V1->print(errs()) : errs() << "  V1: (null)\n";
  // }
  return false; // default: unsigned
}

void BulbasaurCoverageFastPass::TraceCmpBranch(
  Function &F, ArrayRef<Instruction *> CmpTraceTargets) {

  // Count number of valid cmp br.
  uint32_t valid_cmp_br_cnt = CmpTraceTargets.size();

  // This array stores br id.
  GlobalVariable *BranchGuardArray = CreateFunctionLocalArrayInSection(
    valid_cmp_br_cnt, F, Int32Ty, BranchGuardsSectionName
  );

  branches += valid_cmp_br_cnt;

  int iter_cnt = -1;
  int branch_offset = 0;
  for (auto I : CmpTraceTargets) {
    iter_cnt += 1;
    if (CmpInst *CMP = dyn_cast<CmpInst>(I)) {

      Value      *A0 = CMP->getOperand(0);
      Value      *A1 = CMP->getOperand(1);
      
      unsigned TypeSize = 0;

      if (A0->getType()->isIntegerTy()) {
        TypeSize = (cast<IntegerType>(A0->getType()))->getBitWidth();

      }

      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                             : -1;

      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);

      FunctionCallee CallbackFunc;
      // non-equality cmp
      CallbackFunc = BranchTraceCmpFunction[CallbackIdx];
      
      // create one global variable for each switch case
      IRBuilder<> Builder(*C);
      Constant *BranchArrayElemPtr = ConstantExpr::getGetElementPtr(BranchGuardArray->getValueType(), BranchGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(branch_offset)}));

      // Get branch id
      IRBuilder<> IRB(CMP);

      Value *BranchArrayElemValue = IRB.CreateLoad(
        BranchGuardArray->getValueType()->getArrayElementType(),
        BranchArrayElemPtr
      );

      if (auto *BranchArrayInst = llvm::dyn_cast<llvm::Instruction>(BranchArrayElemValue)) {
        SetNoSanitizeMetadata(BranchArrayInst);
      } else {
        errs() << "Error: BranchArrayElemValue is not an Instruction!\n";
      }
      
      // Const arg is the first parameter.
      if (SecondIsConst) {
        IRB.CreateCall(CallbackFunc, {BranchArrayElemValue, A1, A0 });
      } else {
        IRB.CreateCall(CallbackFunc, {BranchArrayElemValue, A0, A1 });
      }
      
      branch_offset++;
    }
  }
}


void BulbasaurCoverageFastPass::TraceStrcmpBranch(
    Function &F, ArrayRef<Instruction *> StrcmpTraceTargets) {

  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);

  uint32_t valid_cmp_br_cnt = StrcmpTraceTargets.size();

  if (valid_cmp_br_cnt == 0) {
    return;
  }

  // This array stores br id.
  GlobalVariable *BranchGuardArray = CreateFunctionLocalArrayInSection(
    valid_cmp_br_cnt, F, Int32Ty, BranchGuardsSectionName
  );

  branches += valid_cmp_br_cnt;

  int branch_offset = 0;
  for (auto I : StrcmpTraceTargets) {
    // handle strcmp(VAR1, const) or strcmp(const, VAR2) 
    if (CallInst *callInst = dyn_cast<CallInst>(I)) {
      Function *Callee = callInst->getCalledFunction();

      FunctionType *FT = Callee->getFunctionType();
      std::string   FuncName = Callee->getName().str();

      bool isPtrRtn = FT->getNumParams() >= 2 &&
                      !FT->getReturnType()->isVoidTy() &&
                      FT->getParamType(0) == FT->getParamType(1) &&
                      FT->getParamType(0)->isPointerTy();

      bool isPtrRtnN = FT->getNumParams() >= 3 &&
                       !FT->getReturnType()->isVoidTy() &&
                       FT->getParamType(0) == FT->getParamType(1) &&
                       FT->getParamType(0)->isPointerTy() &&
                       FT->getParamType(2)->isIntegerTy();
      if (isPtrRtnN) {

        auto intTyOp =
            dyn_cast<IntegerType>(callInst->getArgOperand(2)->getType());
        if (intTyOp) {

          if (intTyOp->getBitWidth() != 32 &&
              intTyOp->getBitWidth() != 64) {

            isPtrRtnN = false;

          }

        }

      }

      bool isMemcmp =
          (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
           !FuncName.compare("CRYPTO_memcmp") ||
           !FuncName.compare("OPENSSL_memcmp") ||
           !FuncName.compare("memcmp_const_time") ||
           !FuncName.compare("memcmpct"));
      isMemcmp &= FT->getNumParams() == 3 &&
                  FT->getParamType(0)->isPointerTy() &&
                  FT->getParamType(1)->isPointerTy() &&
                  FT->getParamType(2)->isIntegerTy();

      bool isStrcmp =
          (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
           !FuncName.compare("xmlStrEqual") ||
           !FuncName.compare("g_strcmp0") ||
           !FuncName.compare("curl_strequal") ||
           !FuncName.compare("strcsequal") ||
           !FuncName.compare("strcasecmp") ||
           !FuncName.compare("stricmp") ||
           !FuncName.compare("ap_cstr_casecmp") ||
           !FuncName.compare("OPENSSL_strcasecmp") ||
           !FuncName.compare("xmlStrcasecmp") ||
           !FuncName.compare("g_strcasecmp") ||
           !FuncName.compare("g_ascii_strcasecmp") ||
           !FuncName.compare("Curl_strcasecompare") ||
           !FuncName.compare("Curl_safe_strcasecompare") ||
           !FuncName.compare("cmsstrcasecmp") ||
           !FuncName.compare("strstr") ||
           !FuncName.compare("g_strstr_len") ||
           !FuncName.compare("ap_strcasestr") ||
           !FuncName.compare("xmlStrstr") ||
           !FuncName.compare("xmlStrcasestr") ||
           !FuncName.compare("g_str_has_prefix") ||
           !FuncName.compare("g_str_has_suffix"));
      isStrcmp &=
          FT->getNumParams() == 2 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0) ==
              IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0);

      bool isStrncmp = (!FuncName.compare("strncmp") ||
                        !FuncName.compare("xmlStrncmp") ||
                        !FuncName.compare("curl_strnequal") ||
                        !FuncName.compare("strncasecmp") ||
                        !FuncName.compare("strnicmp") ||
                        !FuncName.compare("ap_cstr_casecmpn") ||
                        !FuncName.compare("OPENSSL_strncasecmp") ||
                        !FuncName.compare("xmlStrncasecmp") ||
                        !FuncName.compare("g_ascii_strncasecmp") ||
                        !FuncName.compare("Curl_strncasecompare") ||
                        !FuncName.compare("g_strncasecmp"));
      isStrncmp &=
          FT->getNumParams() == 3 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0) ==
              IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0) &&
          FT->getParamType(2)->isIntegerTy();

      bool isGccStdStringStdString =
          Callee->getName().find("__is_charIT_EE7__value") !=
              std::string::npos &&
          Callee->getName().find(
              "St7__cxx1112basic_stringIS2_St11char_traits") !=
              std::string::npos &&
          FT->getNumParams() >= 2 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0)->isPointerTy();

      bool isGccStdStringCString =
          Callee->getName().find(
              "St7__cxx1112basic_stringIcSt11char_"
              "traitsIcESaIcEE7compareEPK") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      bool isLlvmStdStringStdString =
          Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
          Callee->getName().find("_12basic_stringI") != std::string::npos &&
          Callee->getName().find("_11char_traits") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      bool isLlvmStdStringCString =
          Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
          Callee->getName().find("_12basic_stringI") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      if (isGccStdStringCString || isGccStdStringStdString ||
          isLlvmStdStringStdString || isLlvmStdStringCString || isMemcmp ||
          isStrcmp || isStrncmp) {

        isPtrRtnN = isPtrRtn = false;

      }


      Value *A0 = callInst->getArgOperand(0);
      Value *A1 = callInst->getArgOperand(1);
      Value *A2 = NULL;

      bool is_const = false;
      int constant_loc = 0;
      
      if (isConstantStr(A0)) {
        is_const = true;
        constant_loc = 1;
      } else if (isConstantStr(A1)) {
        is_const = true;
        constant_loc = 2;
      }

      // create one global variable for each switch case
      IRBuilder<> Builder(*C);
      Constant *BranchArrayElemPtr = ConstantExpr::getGetElementPtr(BranchGuardArray->getValueType(), BranchGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(branch_offset)}));

      // Get branch id
      IRBuilder<> IRB(callInst);
      Value *BranchArrayElemValue = IRB.CreateLoad(
        BranchGuardArray->getValueType()->getArrayElementType(),
        BranchArrayElemPtr
      );
      if (auto *BranchArrayInst = llvm::dyn_cast<llvm::Instruction>(BranchArrayElemValue)) {
        SetNoSanitizeMetadata(BranchArrayInst);
      } else {
        errs() << "Error: BranchArrayElemValue is not an Instruction!\n";
      }

      // The constant arg is always in first location.
      if (constant_loc == 2) {
        std::swap(A0, A1);
      }
      
      if (isStrcmp) {
        strcmp_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceStrcmpFunction[0], args);
      }
      if (isStrncmp) {
        strncmp_cnt++;

        A2 = callInst->getArgOperand(2);

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        Value               *v3Pbitcast = IRB.CreateBitCast(
            A2, IntegerType::get(*C, A2->getType()->getPrimitiveSizeInBits()));
        Value *v3Pcasted =
            IRB.CreateIntCast(v3Pbitcast, IntegerType::get(*C, 64), false);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(v3Pcasted);

        IRB.CreateCall(BranchTraceStrcmpFunction[1], args);
      }
      if (isMemcmp || isPtrRtnN) {
        memcmp_cnt++;

        A2 = callInst->getArgOperand(2);

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        Value               *v3Pbitcast = IRB.CreateBitCast(
            A2, IntegerType::get(*C, A2->getType()->getPrimitiveSizeInBits()));
        Value *v3Pcasted =
            IRB.CreateIntCast(v3Pbitcast, IntegerType::get(*C, 64), false);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(v3Pcasted);

        IRB.CreateCall(BranchTraceStrcmpFunction[2], args);
      }
      if (isPtrRtn) {
        calls_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));

        IRB.CreateCall(BranchTraceStrcmpFunction[4], args);
      }
      if (isGccStdStringStdString) {
        gccstdstd_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceStrcmpFunction[5], args);
      }
      if (isGccStdStringCString) {
        gccstdc_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceStrcmpFunction[6], args);
      }
      if (isLlvmStdStringStdString) {
        llvmstdstd_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceStrcmpFunction[7], args);
      }
      if (isLlvmStdStringCString) {
        llvmstdc_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceStrcmpFunction[8], args);
      }

      branch_offset++;
    }
  }
}

void BulbasaurCoverageFastPass::TraceNonTermStrcmp(Function &F, ArrayRef<Instruction *> StrcmpTraceTargetsNonTerminator) {
  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);

  uint32_t valid_cmp_br_cnt = StrcmpTraceTargetsNonTerminator.size();

  if (valid_cmp_br_cnt == 0) {
    return;
  }

  // This array stores br id.
  GlobalVariable *BranchGuardArray = CreateFunctionLocalArrayInSection(
    valid_cmp_br_cnt, F, Int32Ty, BranchGuardsSectionName
  );

  branches += valid_cmp_br_cnt;

  int branch_offset = 0;
  for (auto I : StrcmpTraceTargetsNonTerminator) {
    // handle strcmp(VAR1, const) or strcmp(const, VAR2) 
    if (CallInst *callInst = dyn_cast<CallInst>(I)) {
      Function *Callee = callInst->getCalledFunction();

      FunctionType *FT = Callee->getFunctionType();
      std::string   FuncName = Callee->getName().str();

      bool isPtrRtn = FT->getNumParams() >= 2 &&
                      !FT->getReturnType()->isVoidTy() &&
                      FT->getParamType(0) == FT->getParamType(1) &&
                      FT->getParamType(0)->isPointerTy();

      bool isPtrRtnN = FT->getNumParams() >= 3 &&
                       !FT->getReturnType()->isVoidTy() &&
                       FT->getParamType(0) == FT->getParamType(1) &&
                       FT->getParamType(0)->isPointerTy() &&
                       FT->getParamType(2)->isIntegerTy();
      if (isPtrRtnN) {

        auto intTyOp =
            dyn_cast<IntegerType>(callInst->getArgOperand(2)->getType());
        if (intTyOp) {

          if (intTyOp->getBitWidth() != 32 &&
              intTyOp->getBitWidth() != 64) {

            isPtrRtnN = false;

          }

        }

      }

      bool isMemcmp =
          (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
           !FuncName.compare("CRYPTO_memcmp") ||
           !FuncName.compare("OPENSSL_memcmp") ||
           !FuncName.compare("memcmp_const_time") ||
           !FuncName.compare("memcmpct"));
      isMemcmp &= FT->getNumParams() == 3 &&
                  FT->getParamType(0)->isPointerTy() &&
                  FT->getParamType(1)->isPointerTy() &&
                  FT->getParamType(2)->isIntegerTy();

      bool isStrcmp =
          (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
           !FuncName.compare("xmlStrEqual") ||
           !FuncName.compare("g_strcmp0") ||
           !FuncName.compare("curl_strequal") ||
           !FuncName.compare("strcsequal") ||
           !FuncName.compare("strcasecmp") ||
           !FuncName.compare("stricmp") ||
           !FuncName.compare("ap_cstr_casecmp") ||
           !FuncName.compare("OPENSSL_strcasecmp") ||
           !FuncName.compare("xmlStrcasecmp") ||
           !FuncName.compare("g_strcasecmp") ||
           !FuncName.compare("g_ascii_strcasecmp") ||
           !FuncName.compare("Curl_strcasecompare") ||
           !FuncName.compare("Curl_safe_strcasecompare") ||
           !FuncName.compare("cmsstrcasecmp") ||
           !FuncName.compare("strstr") ||
           !FuncName.compare("g_strstr_len") ||
           !FuncName.compare("ap_strcasestr") ||
           !FuncName.compare("xmlStrstr") ||
           !FuncName.compare("xmlStrcasestr") ||
           !FuncName.compare("g_str_has_prefix") ||
           !FuncName.compare("g_str_has_suffix"));
      isStrcmp &=
          FT->getNumParams() == 2 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0) ==
              IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0);

      bool isStrncmp = (!FuncName.compare("strncmp") ||
                        !FuncName.compare("xmlStrncmp") ||
                        !FuncName.compare("curl_strnequal") ||
                        !FuncName.compare("strncasecmp") ||
                        !FuncName.compare("strnicmp") ||
                        !FuncName.compare("ap_cstr_casecmpn") ||
                        !FuncName.compare("OPENSSL_strncasecmp") ||
                        !FuncName.compare("xmlStrncasecmp") ||
                        !FuncName.compare("g_ascii_strncasecmp") ||
                        !FuncName.compare("Curl_strncasecompare") ||
                        !FuncName.compare("g_strncasecmp"));
      isStrncmp &=
          FT->getNumParams() == 3 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0) ==
              IntegerType::getInt8Ty(CurModule->getContext())->getPointerTo(0) &&
          FT->getParamType(2)->isIntegerTy();

      bool isGccStdStringStdString =
          Callee->getName().find("__is_charIT_EE7__value") !=
              std::string::npos &&
          Callee->getName().find(
              "St7__cxx1112basic_stringIS2_St11char_traits") !=
              std::string::npos &&
          FT->getNumParams() >= 2 &&
          FT->getParamType(0) == FT->getParamType(1) &&
          FT->getParamType(0)->isPointerTy();

      bool isGccStdStringCString =
          Callee->getName().find(
              "St7__cxx1112basic_stringIcSt11char_"
              "traitsIcESaIcEE7compareEPK") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      bool isLlvmStdStringStdString =
          Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
          Callee->getName().find("_12basic_stringI") != std::string::npos &&
          Callee->getName().find("_11char_traits") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      bool isLlvmStdStringCString =
          Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
          Callee->getName().find("_12basic_stringI") != std::string::npos &&
          FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
          FT->getParamType(1)->isPointerTy();

      if (isGccStdStringCString || isGccStdStringStdString ||
          isLlvmStdStringStdString || isLlvmStdStringCString || isMemcmp ||
          isStrcmp || isStrncmp) {

        isPtrRtnN = isPtrRtn = false;

      }


      Value *A0 = callInst->getArgOperand(0);
      Value *A1 = callInst->getArgOperand(1);
      Value *A2 = NULL;

      bool is_const = false;
      int constant_loc = 0;
      
      if (isConstantStr(A0)) {
        is_const = true;
        constant_loc = 1;
      } else if (isConstantStr(A1)) {
        is_const = true;
        constant_loc = 2;
      }

      // create one global variable for each switch case
      IRBuilder<> Builder(*C);
      Constant *BranchArrayElemPtr = ConstantExpr::getGetElementPtr(BranchGuardArray->getValueType(), BranchGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(branch_offset)}));

      // Get branch id
      IRBuilder<> IRB(callInst);
      Value *BranchArrayElemValue = IRB.CreateLoad(
        BranchGuardArray->getValueType()->getArrayElementType(),
        BranchArrayElemPtr
      );
      if (auto *BranchArrayInst = llvm::dyn_cast<llvm::Instruction>(BranchArrayElemValue)) {
        SetNoSanitizeMetadata(BranchArrayInst);
      } else {
        errs() << "Error: BranchArrayElemValue is not an Instruction!\n";
      }

      // The constant arg is always in first location.
      if (constant_loc == 2) {
        std::swap(A0, A1);
      }
      
      if (isStrcmp) {
        strcmp_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[0], args);
      }
      if (isStrncmp) {
        strncmp_cnt++;

        A2 = callInst->getArgOperand(2);

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        Value               *v3Pbitcast = IRB.CreateBitCast(
            A2, IntegerType::get(*C, A2->getType()->getPrimitiveSizeInBits()));
        Value *v3Pcasted =
            IRB.CreateIntCast(v3Pbitcast, IntegerType::get(*C, 64), false);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(v3Pcasted);

        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[1], args);
      }
      if (isMemcmp || isPtrRtnN) {
        memcmp_cnt++;

        A2 = callInst->getArgOperand(2);

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        Value               *v3Pbitcast = IRB.CreateBitCast(
            A2, IntegerType::get(*C, A2->getType()->getPrimitiveSizeInBits()));
        Value *v3Pcasted =
            IRB.CreateIntCast(v3Pbitcast, IntegerType::get(*C, 64), false);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(v3Pcasted);

        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[2], args);
      }
      if (isPtrRtn) {
        calls_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));

        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[4], args);
      }
      if (isGccStdStringStdString) {
        gccstdstd_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[5], args);
      }
      if (isGccStdStringCString) {
        gccstdc_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[6], args);
      }
      if (isLlvmStdStringStdString) {
        llvmstdstd_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[7], args);
      }
      if (isLlvmStdStringCString) {
        llvmstdc_cnt++;

        std::vector<Value *> args;
        Value               *v1Pcasted = IRB.CreatePointerCast(A0, i8PtrTy);
        Value               *v2Pcasted = IRB.CreatePointerCast(A1, i8PtrTy);
        args.push_back(BranchArrayElemValue);
        args.push_back(v1Pcasted);
        args.push_back(v2Pcasted);
        args.push_back(ConstantInt::get(Int64Ty, STRCMP_MAX_LEN));
        
        IRB.CreateCall(BranchTraceNonTermStrcmpFunction[8], args);
      }

      branch_offset++;
    }
  }
}

void BulbasaurCoverageFastPass::TraceSwitchBranch(Function &F, ArrayRef<Instruction *> SwitchTraceTargets, ArrayRef<ConstantInt *> case_val_list, std::vector<int> int_val_list) {
  uint32_t valid_cmp_br_cnt = 0;
  int caseCnt = -1;
  for (auto I : SwitchTraceTargets) {
    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {
      Value* op1 = SI->getCondition();
      //uint64_t TypeSize = DL->getTypeStoreSizeInBits(op1->getType());
      unsigned TypeSize = (cast<IntegerType>(op1->getType()))->getBitWidth();
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      
      int num_cases = SI->getNumCases();
      valid_cmp_br_cnt += num_cases;
      caseCnt += num_cases;
    
      // handle default case: choose a target value for defacut case
      caseCnt += 1;
      Value* op2 = case_val_list[caseCnt]; // default case value
      
      if (!op2){
        llvm::errs()<< "\n[LOG] skip to instrument an empty default case.\n";
        continue;
      }
      valid_cmp_br_cnt++;
    }
  }

  if (valid_cmp_br_cnt == 0) {
    return;
  }

  // This array stores br id.
  GlobalVariable *BranchGuardArray = CreateFunctionLocalArrayInSection(
    valid_cmp_br_cnt, F, Int32Ty, BranchGuardsSectionName
  );

  branches += valid_cmp_br_cnt;

  int iter_cnt = -1;
  caseCnt = -1;
  int branch_offset = 0;
  for (auto I : SwitchTraceTargets) {
    iter_cnt += 1;
    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      Value* op1 = SI->getCondition();
      //uint64_t TypeSize = DL->getTypeStoreSizeInBits(op1->getType());
      unsigned TypeSize = (cast<IntegerType>(op1->getType()))->getBitWidth();
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      
      // Switch is unsigned.
      auto CallbackFunc = BranchTraceCmpFunction[CallbackIdx];
      
      int num_cases = SI->getNumCases();
      
      // std::string ldInst_str;
      // llvm::raw_string_ostream ldss(ldInst_str);
      // SancovForSwitch[iter_cnt]->print(ldss);
      // ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());

      for (int i = 0; i< num_cases;i++) {
        caseCnt += 1;
        // std::string str,cmp_str, key;
        // llvm::raw_string_ostream ss(str);
        // SI->print(ss);
        // str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
        // cmp_str = str;
        
        // std::string target_str;
        // llvm::raw_string_ostream lds(target_str);
        // Instruction* loadInst = case_target_list[caseCnt];
        // int cur_case_val = int_val_list[caseCnt];
        // loadInst->print(lds);
        // target_str.erase(std::remove(target_str.begin(), target_str.end(), '\n'), target_str.cend());
        // int instrument_id = *InstrumentCntPtr;

        // // br_dist_edge_id|inst: sancov id |inst: cmp/strcmp/sw| inst: select| case_val; inst: sw target
        // // string concatination
        // std::ostringstream oss;
        // oss << "3|" << instrument_id << "|" << ldInst_str << "| | |"  << cur_case_val << ";" << target_str << "|" << TypeSize / 8 << "\n";
        // datalog << oss.str();

        // create one global variable for each switch case
        Type *ElemPtrType = Int32Ty->getPointerTo();
        IRBuilder<> Builder(*C);
        Constant *BranchArrayElemPtr = ConstantExpr::getGetElementPtr(BranchGuardArray->getValueType(), BranchGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(branch_offset)}));

        // Get branch id
        IRBuilder<> IRB(SI);
        Value *BranchArrayElemValue = IRB.CreateLoad(
          BranchGuardArray->getValueType()->getArrayElementType(),
          BranchArrayElemPtr
        );
        if (auto *BranchArrayInst = llvm::dyn_cast<llvm::Instruction>(BranchArrayElemValue)) {
          SetNoSanitizeMetadata(BranchArrayInst);
        } else {
          errs() << "Error: BranchArrayElemValue is not an Instruction!\n";
        }

        Value* op2 = case_val_list[caseCnt];
        IRB.CreateCall(CallbackFunc, {BranchArrayElemValue, op2, op1});
        // update global instrumentCnt if we instrument a new site, update hash map
        branch_offset++;
      }
    
      // handle default case: choose a target value for defacut case
      
      caseCnt += 1;
      Value* op2 = case_val_list[caseCnt]; // default case value   
      
      if (!op2){
        continue;
      }

      // std::string str, cmp_str, key;
      // llvm::raw_string_ostream ss(str);
      // SI->print(ss);
      // str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
      // cmp_str = str;
      
      // std::string target_str;
      // llvm::raw_string_ostream lds(target_str);
      // Instruction* loadInst = case_target_list[caseCnt];
      // int cur_case_val = int_val_list[caseCnt];
      // loadInst->print(lds);
      // target_str.erase(std::remove(target_str.begin(), target_str.end(), '\n'), target_str.cend());
      // int instrument_id = *InstrumentCntPtr;
      
      // std::ostringstream oss;
      // oss << "3|" << instrument_id << "|" << ldInst_str << "| | |"  << cur_case_val << ";" << target_str << "|" << TypeSize / 8 << "\n";
      // datalog << oss.str();

      // create one global variable for each switch case
      Type *ElemPtrType = Int32Ty->getPointerTo();
      IRBuilder<> Builder(*C);
      Constant *BranchArrayElemPtr = ConstantExpr::getGetElementPtr(BranchGuardArray->getValueType(), BranchGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(branch_offset)}));
      
      // Get branch id
      IRBuilder<> IRB(SI);
      Value *BranchArrayElemValue = IRB.CreateLoad(
        BranchGuardArray->getValueType()->getArrayElementType(),
        BranchArrayElemPtr
      );
      if (auto *BranchArrayInst = llvm::dyn_cast<llvm::Instruction>(BranchArrayElemValue)) {
        SetNoSanitizeMetadata(BranchArrayInst);
      } else {
        errs() << "Error: BranchArrayElemValue is not an Instruction!\n";
      }
        
      IRB.CreateCall(CallbackFunc, {BranchArrayElemValue, op2, op1});
      branch_offset++;
    }
  }
}
