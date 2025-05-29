#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {
struct AFLDemoPass : public ModulePass {
  static char ID;
  AFLDemoPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    LLVMContext &C = M.getContext();

    // Declare or insert the __demo_crash function
    FunctionCallee demoCrashFunc = M.getOrInsertFunction(
        "__demo_crash", FunctionType::get(Type::getVoidTy(C), false));

    for (auto &F : M) {
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto *call = dyn_cast<CallInst>(&I)) {
            Function *calledFunc = call->getCalledFunction();
            if (!calledFunc) continue;
            if (calledFunc->getName() != "system") continue;

            Value *arg = call->getArgOperand(0)->stripPointerCasts();

            // Skip constant global strings like system("echo AAA")
            if (auto *gv = dyn_cast<GlobalVariable>(arg)) {
              if (gv->hasInitializer()) {
                if (isa<ConstantDataArray>(gv->getInitializer())) {
                  continue; // This is a safe, constant string.
                }
              }
            }

            // Not a constant -> likely user-controlled -> potential injection
            IRBuilder<> IRB(call);
            IRB.CreateCall(demoCrashFunc);
          }
        }
      }
    }

    return true;
  }
};
}

char AFLDemoPass::ID = 0;
static RegisterPass<AFLDemoPass> X("afl_demo_pass", "AFL++ Demo Pass", false, false);
