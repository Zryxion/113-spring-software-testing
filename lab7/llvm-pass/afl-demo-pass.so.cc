#define AFL_LLVM_PASS

#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

class AFLDEMOPass : public PassInfoMixin<AFLDEMOPass> {
 public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    FunctionCallee crashFn = M.getOrInsertFunction("__demo_crash", FunctionType::get(Type::getVoidTy(C), false));

    for (auto &F : M) {
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto *call = dyn_cast<CallInst>(&I)) {
            Function *calledFunc = call->getCalledFunction();
            if (!calledFunc) continue;

            if (calledFunc->getName() == "system") {
              // Only one arg to system()
              if (call->arg_size() != 1) continue;

              Value *arg = call->getArgOperand(0);
              // Check if it's a constant string
              if (isa<ConstantExpr>(arg) || isa<ConstantDataArray>(arg) || isa<Constant>(arg)) {
                continue; // Constant string → safe
              }

              // If not constant, it's dynamic/tainted → add crash
              IRBuilder<> IRB(call);
              CallInst *crashCall = IRB.CreateCall(crashFn);
              crashCall->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
            }
          }
        }
      }
    }

    return PreservedAnalyses::all();
  }
};

}  // namespace

// Register the pass
extern "C" ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "AFLDEMOPass",
    "v0.1",
    [](PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(AFLDEMOPass());
        });
    }
  };
}
