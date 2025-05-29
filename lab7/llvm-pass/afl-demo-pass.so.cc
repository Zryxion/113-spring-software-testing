#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

using namespace llvm;

namespace {

class AFLDEMOPass : public PassInfoMixin<AFLDEMOPass> {
 public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    Type *VoidTy = Type::getVoidTy(C);
    FunctionCallee demo_crash = M.getOrInsertFunction("__demo_crash", VoidTy);

    for (Function &F : M) {
      if (F.isDeclaration()) continue;

      StringRef fn = F.getName();
      if (fn.startswith("_start") || fn.startswith("__libc_csu") ||
          fn.startswith("__afl_") || fn.startswith("__asan") ||
          fn.startswith("asan.") || fn.startswith("llvm."))
        continue;

      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (auto *call = dyn_cast<CallInst>(&I)) {
            Function *calledFunc = call->getCalledFunction();
            if (!calledFunc) continue;

            if (calledFunc->getName() == "system") {
              // Only consider non-constant arguments (possible user input)
              Value *arg = call->getArgOperand(0);
              if (!isa<Constant>(arg)) {
                IRBuilder<> IRB(call);
                IRB.CreateCall(demo_crash)->setMetadata(
                    M.getMDKindID("nosanitize"), MDNode::get(C, None));
              }
            }
          }
        }
      }
    }

    return PreservedAnalyses::all();
  }
};

}  // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "AFLDEMOPass", "v0.2",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef, ModulePassManager &MPM,
           ArrayRef<PassBuilder::PipelineElement>) {
          MPM.addPass(AFLDEMOPass());
          return true;
        });
    }
  };
}
