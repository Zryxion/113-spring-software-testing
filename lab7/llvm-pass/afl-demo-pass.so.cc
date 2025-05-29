#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <string>
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class AFLDEMOPass : public PassInfoMixin<AFLDEMOPass> {

 public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AFLDEMOPass", "v0.1",
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(AFLDEMOPass());
                });
          }};
}

PreservedAnalyses AFLDEMOPass::run(Module &M, ModuleAnalysisManager &) {

  LLVMContext &C = M.getContext();
  Type *VoidTy = Type::getVoidTy(C);
  FunctionCallee demo_crash = M.getOrInsertFunction("__demo_crash", VoidTy);

  for (auto &F : M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (auto *call = dyn_cast<CallInst>(&I)) {
          Function *callee = call->getCalledFunction();
          if (!callee) continue;

          if (callee->getName() == "system") {
            Value *arg = call->getArgOperand(0);

            if (!isa<ConstantDataArray>(arg->stripPointerCasts())) {
              // Likely attacker-controlled string, inject crash
              IRBuilder<> IRB(call);
              IRB.CreateCall(demo_crash)->setMetadata(M.getMDKindID("nosanitize"),
                                                       MDNode::get(C, {}));
            }
          }
        }
      }
    }
  }

  return PreservedAnalyses::all();
}
