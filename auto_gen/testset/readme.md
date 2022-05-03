## Generated TestSet

We use [This Project](https://github.com/nen9mA0/Instruction-Generator) to generate testset. It parse the file that [Intel XED](#https://github.com/intelxed/xed) generate, then build a structure which is like a database (But actually it's not a database) and traverse this structure with some conditions. But I think it's an unfinished project, and if somebody interested in it, feel free to send issues or contact me.

### List of TestSet

| Filename                    | Details                                                      |
| --------------------------- | ------------------------------------------------------------ |
| base_ring3.txt              | Most of Ring3 instructions in X86 instruction set.           |
| base_noring3.txt            | Most of instructions that cannot run in Ring3. Theoretically these instructions should never appear in a obfuscated program because the obfuscator are mostly used to obfuscate an user program. But to test our theory, we test some Ring0 instruction here, and of course they will trigger an exception. |
| base_branch.txt             | Branch instructions, actually we didn't test these instructions because they change the control flow, and leave them for future work. |
| base_strop.txt              | IO and string instructions, we didn't test these instructions because we need to specify the memory context for them. We also leave them for future work. |
| base_ring3_need_specify.txt | Some special Ring3 instructions that we need to set the context carefully in order to execute them normally. We also leave them for future work. |
| base_notest.txt             | We think these instructions are unnecessary to test.         |
| sse.txt                     | Some SSE instructions that we test. Most of them are in SSE2 instruction set. |
| x87.txt                     | The x87 FPU instructions that we test.                       |

