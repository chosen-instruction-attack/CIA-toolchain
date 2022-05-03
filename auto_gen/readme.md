### 自动化生成程序

caller.py根据config自动调用下列文件

* caller.py
  * insset_test.py
  * FetchTestSet.py
  * AnchorFinder.py
  * repair_anchorfinder.py
  * LogCompare.py

#### caller.py

##### 功能

根据传入的json配置文件来自动化调用下面的几个脚本，主要用于自动化测试，减少人工输入命令行和整合各个脚本的输出报告的繁琐工作

##### 命令行参数

```
python caller.py -c configfile [-d]
```

* -c  配置文件，是一个json文件，格式下面有具体描述
* -d  debug模式

##### 配置文件

配置文件是一个json文件，每个配置为一个字典的形式，配置文件则是一个由配置组成的列表，因此可以同时给出多个测试配置，脚本将自动化顺序执行这些配置指定的操作。

下面列出配置支持的关键字和选项

| 关键字            | 用途 |
| :---------------- | ---- |
| state | 必选，若为enable则表示该条配置生效 |
| vmp               | 必选，用于指定待测试vmp的类型 |
| testset           | 必选，用于指定待测试的指令列表 |
|action | 必选，用于指定当前需要对该测试集执行的操作，可选项见下面描述 |
| output_dir        |      |
| c_template        |      |
| makefile_template |      |
| testset_log_dir   |      |
| testset_out_dir   |      |
| anchor_log        |      |
| anchor_out        |      |
|anchor | 可选，用来指定C模板文件中使用的锚点指令，默认为 "cmpxchg eax, eax" |

action参数的选项

* clean  清除所有的输出文件和log文件（但不包括生成的程序和log）

  该自动化程序为了保证实验数据不会被误操作而覆盖，默认情况下当目录已经存在输出文件与log文件时会终止操作并报错。当确定要覆盖文件时可以指定clean操作删除这些log和输出文件。

* gen  在指定的输出目录生成测试集的C源文件和makefile

  实际执行的命令是调用 [insset_test.py](#insset_test.py)

* make  编译exe文件，并生成3次混淆后的程序（若需要更多次需要修改makefile文件）

  实际执行的命令是 `mkdir err_log; make build`

* pin  使用pintools生成trace文件

  实际执行的命令是 `make pin`

* test  测试并找到锚点指令，生成报告

  实际执行的命令是调用 [FetchTestSet.py](FetchTestSet.py) 和 [AnchorFinder.py](#AnchorFinder.py)

* 【Undone】anchor_pin  使用pintools生成trace文件，这里使用的是 anchorfinder.cpp（见pintools/readme.md），因此需要使用不同的命令行调用

  实际执行的命令是 `make anchor_pin`

##### 输出文件与目录

该程序为了标准化流程，会根据配置自动生成一些目标的文件与文件夹名字，下面主要描述生成文件名的规则，这里结合 [sample.json](config/sample.json) 的内容进行阐述

* C源文件、exe、混淆后文件和trace文件的生成目录：  `[testset]_[vmp]` 

  sample.json中生成的目录名为： `just4test_themida_tiger`

* 

#####  注意事项

**注意**：若在action中指定了gen，程序将生成C源文件，若指定了make，则将进行编译与混淆。若action中同时指定了gen与make，需要注意若第二次运行了该配置，则上一次生成的源文件、程序等均会被覆盖。



#### insset_test.py

##### 功能

该程序接收待测试指令列表，根据不同混淆器的C源文件模板以及makefile模板生成测试程序（每条测试指令对应一个程序），并输出到指定的目录下

生成的文件会将C源文件模板中的`%REPLACE%`替换为待测试指令，并将待测试指令的hex表示以注释的形式放在源文件的第一行以方便后续识别锚点。文件的命名规则为 `指令助记符+数字+.c` ，其中数字是按照当前有几个助记符相同的指令确定的

```
假设当前测试的指令列表是
mov  cx, 0xa
mov  cx, dx
则指令对应的文件名分别为
mov0.c
mov1.c
```

##### 命令行参数

```
python insset_test.py -i testset -o output_dir -t c_template -m makefile_template -n makefile_template_config_name -p makefile_template_config_path [-a anchor] [-l log_path]
```

* -i  待测试命令的文本文件
* -o  .c文件的输出目录
* -t  .c文件的模板
* -m  makefile模板
* -n  makfile config的配置名
* -p  makefile config的配置文件路径
* -a  指定的anchor，默认为 `cmpxchg eax, eax`
* -l  log文件位置，默认为`""`，此时只会从控制台输出

##### Log

这个文件输出的log内容为一个文件名与其对应的测试指令的列表，格式如下

```
File:                   Ins:
================================
mov0.c:                 mov  cx, 0xa
mov1.c:                 mov  cx, dx
```

##### 注意事项

* 因为 **Code Virtualizer** 和 **Themida** 在使用命令行调用的时候需要指定输出目录，因此该程序会根据makefile模板的名字（判断依据为是否出现 **cv** 或 **themida** ）对makefile的DIR变量进行替换，因此若需要自定义makefile请注意修改名字
* 此外待测试指令的hex表示是直接使用keystone的反汇编结果，默认是32位模式，若需要测试其他位数的指令请到第10行修改初始化的keystone类

##### 一些可以设置的全局变量

| name        | function                                                     |
| ----------- | ------------------------------------------------------------ |
| suffix      | 源码文件的后缀，默认是".c"                                   |
| ins_hex_lst | 这个字典存放了一些capstone反汇编结果与pintools反汇编结果不同的指令，因为这可能影响后续的结果 |
| except_ins  | 这个字典存放了一些测试指令集中无法被gcc正确汇编的指令        |
| ks          | 汇编器，这里默认使用的是keystone的32位汇编器，若需要测试其他位数的指令需要修改 |



#### FetchTestSet.py

##### 功能

获取执行makefile后，实际执行成功的测试集，与执行失败的程序。其中执行失败的程序分为gcc编译失败、VMP混淆失败、pintool生成log失败

##### 命令行参数

```
python FetchTestSet.py  -d dir1 dir2 ...  [-b base_dir  -a anchor_str  -l logfile]
```

* -d  要获取测试集的目录名，可以指定多个目录
* -b  测试集目录的父目录，这里主要是为了减少-d需要传入的参数
* -a  anchor指令
* -l  log文件位置，默认为`""`，此时只会从控制台输出

##### Log

标准输出默认只会输出Full Test Set中的指令

输出的文件log格式如下

```
==============Full Test Set==============
    =============test=============
file: aaa0  	  ins: aaa
file: adc0  	  ins: adc  byte ptr [esi + edi], 0xa
==============GCC Failed Set==============
file: bsf0  	  ins: bsf  cx, dx
///===========Failed Set: 1===========\\\
==============VMP Failed Set==============
file: cmovae0  	  ins: cmovae  cx, word ptr [esi + edi]
==============LOG Failed Set==============
file: mov1  	  ins: mov  cx, dx
///===========Failed Set: 2===========\\\
==============VMP Failed Set==============
==============LOG Failed Set==============
file: mov1  	  ins: mov  cx, dx
```

如上例，输出分为下列几个部分

* Full Test Set

  该程序会首先获取目标文件夹中生成了几次混淆程序，获取的方式如下节 *注意事项* 所述，如某条指令对应的混淆程序全部存在于文件夹中，则认为该指令的测试集生成完全成功，会被归类为 **Full Test Set** 并输出。输出的第二行test为测试程序所在文件夹的名称

  此例中，aaa0和adc0都被归为此类，说明文件夹中必存在（注意这里生成了两次混淆后的程序）

  ```
  aaa0.c	aaa0.exe	aaa0_1.vmp.exe	aaa0_2.vmp.exe
  adc0.c	adc0.exe	adc0_1.vmp.exe	adc0_2.vmp.exe
  ```

* GCC Failed Set

  根据目标文件夹中指令对应的exe文件是否存在，若不存在则被归类为 **GCC Failed Set**

  此例中，bsf0被归为此类，说明bsf.c没有成功生成bsf.exe

* Failed Set: n

  因为接下来的文件可能被生成多次（即从同一个exe文件生成多个vmp文件），因此这里的n表示第n次生成的测试集对应的报告

  * VMP Failed Set

    混淆失败的程序

    此例中，cmovae0第一次被归为此类，但第二次没有，说明第一次混淆失败而第二次成功，即文件夹中存在 `cmovae0_2.vmp.exe` 但不存在`cmovae0_1.vmp.exe` （这种情况在实验中确实可能出现）

  * LOG Failed Set

    log生成失败的程序

    此例中，mov1两次都被归为此类，说明 `mov1_1.vmp.exe` 和 `mov1_2.vmp.exe` 都无法正确生成log

##### 注意事项

* 获取测试集时是根据文件名获取的，如文件夹中有文件 `mov0.c` 则会查找对应的 `mov0.exe` 来判断gcc是否编译失败，若编译成功则查找 `mov0_1.vmp.exe mov0_2.vmp.exe` 等判断VMP是否混淆失败，若混淆成功则查找 `mov0_1.log mov0_2.log` 判断是否log生成失败。

  其中，在查找VMP混淆后的程序时，会先扫描整个文件夹判断每个exe生成了多少个混淆程序，并以扫描到的最大值为准

  举例说明：mov0.c 和 mov1.c 分别生成了两次和三次混淆，文件名为

  ```
  mov0_1.vmp.exe
  mov0_2.vmp.exe
  mov1_1.vmp.exe
  mov1_2.vmp.exe
  mov1_3.vmp.exe
  ```

  此时程序认为每个程序都生成了三次混淆，并且认为mov0_3.vmp.exe生成失败，会体现在最后生成的log中

* 这里的-a选项指定anchor时**没有进行任何格式和语法的检查**，若anchor无法与源文件中的指令匹配，则打印出的ins为空，内容也存在错误。因此需要注意

##### 一些可以设置的全局变量

该算法依赖于文件的后缀名，因此若需要指定文件后缀，可以到 [suffix.py](#suffix.py) 进行设置



#### AnchorFinder.py

##### 功能

该脚本用于根据跑出的log判断对应的测试指令是否为锚点

##### 命令行参数

```
python AnchorFinder.py -d dir -m mode [-a anchor -b base_dir -l logfile]
```

* -d  存放log的目录名
* -m  查找锚点的模式，目前有3anchor和retanchor两种模式，具体算法见下面
* -a  指定的anchor，默认为 `cmpxchg eax, eax`
* -b  测试集目录的父目录
* -l  log文件位置，默认为`""`，此时只会从控制台输出

##### 算法原理

###### 实验方法

首先在CIA实验中，为了保证结果的准确性，以及保证分析算法对于虚拟机变形技术的鲁棒性，我们对于同一个exe使用相同配置生成了三个对应的混淆程序，并分别获取其log。在经过该脚本分析后，若脚本对于同一个exe生成的三个混淆程序的log，都认为其是锚点，则该测试指令被认为是一个锚点

###### 算法

anchor的查找方法目前主要为两种

* 3anchor  该方法的判定规则为：若被测试指令在log中出现过且仅出现一次，则视其为锚点

  该方法基于的假设是，若虚拟机为某条指令设计了相应的handler，则该条指令基本不可能原样出现在混淆后的程序中。而出现一次的限定主要是为了防止该指令本身被用于混淆中

* retanchor  该方法的判定规则为：若被测试的指令在log中出现且前一条指令是ret，则视其为锚点

  使用该方法的原因是，我们通过对大量不同类型与不同指令的log的分析，发现目前大多数虚拟机在遇到锚点前执行context switch保存环境时，最后都会通过ret返回，再执行待测试的锚点指令

###### 评估

* 3anchor  该方法找到的锚点准确性可能较低，因为不是根据context switch特征进行锚点查找，因此可能某些指令在执行前实际上没有经过context switch，也被判定为锚点。但该方法测试出的锚点可能在实际应用中价值较高，因为其特征明显（仅在log中出现一次）。

  这种情况主要在VMP3中出现，因为VMP3中含有对内存操作数的混淆，一般被混淆后的寄存器可能是esi edi等，因此但对于类似下述指令

  ```
  adc ecx, dword ptr [esi]
  ```

  混淆后的结果可能保持原样，于是会被3anchor判定为锚点，但实际上这条指令在执行前没有明显的context switch

* retanchor  该方法找到的锚点准确性较高，其可以避免上述的3anchor问题。此外对于某条指令可能存在指令本身是锚点，且该指令被大量用于混淆的情况可以使用该方法正确区分。

  但该方法主要基于context switch末尾一般是ret的启发式算法，因此也可能产生误判，虽然目前对于大多数混淆器该启发式算法暂时有效。

  其中一种误判情况也是在VMP3中被发现的，因为VMP3会使用 `push 跳转地址; ret;` 的方式实现jmp，而一般使用jmp跳转的情况是没有进行context switch的。

  但这种误判出现的概率较小，因为 `push ret` 与 `jmp` 的代换属于虚拟机的变形技术，所以具有一定的随机性，而由于我们的测试对象包含了同一个程序生成的三个混淆程序，因此可以一定程度上减少误判概率。

总而言之，上述算法从目前的实验结果来看，准确性尚可。但对于之后的工作来说，我们认为更完善的启发式算法是必要的。

##### Log

输出的文件log格式如下

```
aaa0_1:
LOG LENGTH TOO SHORT
aaa0_3:
==== only occur one time ====
    436b46: aaa
adc0_1:
LOG LENGTH TOO SHORT
adc0_2:
LOG LENGTH TOO SHORT
bsf0_1:
==== only occur one time ====
    410775: bsf  cx, dx
bsf0_2:
==== only occur one time ====
    433c57: bsf  cx, dx
bsf0_3:
==== only occur one time ====
    420bdf: bsf  cx, dx
bsf0_4:
==== only occur one time ====
    45ffff: bsf  cx, dx
========= Anchor =========
bsf  cx, dx  ; 4 ; File: X:\anti_vmp\VM-CSA\auto_gen\just4test\test\bsf0.c
========= Not Always Appear =========
aaa ; 1/2 ; [1] ; File: I:\Project\anti_vmp\VM-CSA\auto_gen\just4test\test\aaa0.c
========= Appear Multiple Times =========
=== No EXE ===
=== No VMP ===
=== No LOG ===
=== Loss VMP ===
aaa0 : 1/4
=== Loss LOG ===
aaa0 : 1/4
=== LOG TOO SHORT ===
aaa0 : 1
adc0 : 2
```

如上例所示，下面为各个部分的释义

* 前面的部分

  * 对于每个找到了被测指令的trace文件，都会显示如下内容：
    * 当被测试指令只在trace中出现一次时，会显示 `==== only occur one time ====` 
    * 否则会显示 `____ occur %d times ____`
  * 对于每个长度小于 `log_threshold` 的trace文件，都会显示 `LOG LENGTH TOO SHORT`

* 统计部分

  *  `========= Anchor =========` 表示找到的符合anchor定义的指令

    第一列为指令，第二列为一共有几个有效的trace文件，第三列为对应源文件的路径

  * `========= Not Always Appear =========` 表示可以在trace文件中找到指令，但不一定在每个trace中都能找到

    第一列为指令，第二列为出现该指令的trace数/所有有效trace数，第三列为一个列表，表示在有出现该指令的trace中分别出现了几次，第四列为对应源文件路径

  * `========= Appear Multiple Times =========` 表示可以在每个trace文件中找到指令，但不一定都只出现一次

    第一列为指令，第二列为只出现一次该指令的trace数/所有有效trace数，第三列为一个列表，表示在trace中分别出现了几次，第四列为对应源文件路径

  加入后两个统计主要是因为在实际测试中可能出现各种情况，而后两种情况中都有可能实际上是锚点指令但由于各种原因（混淆器bug、pintools崩溃等）而没有被统计为锚点，因此有些需要手工核对

  * `=== No EXE ===` 表示有哪些源文件编译失败

  * `=== No VMP ===` 表示有哪些程序混淆全部失败

  * `=== No LOG ===` 表示有哪些程序在记录trace时全部失败

  * `=== Loss VMP ===` 表示有哪些程序混淆时部分失败

    第一列为文件名，第二列为混淆失败的个数/原本要生成的混淆程序个数

  * `=== Loss LOG ===` 表示有哪些程序记录trace时部分失败

    第一列为文件名，第二列为记录trace失败的个数/原本要记录的trace个数

  * `=== LOG TOO SHORT ===` 统计有多少log长度小于 `log_threshold`

最后两行显示的是最终找到的符合条件的anchor指令（条件见 [算法](#算法)），后面的File指出该anchor指令所对应的源文件。

##### 注意事项

* 因为测试时，一般每个exe样本不止会生成一个混淆后的样本（理论上混淆后样本越多，测出的锚点准确性越高），所以脚本会遍历测试文件夹的各个文件名来确定测试样本的总数。因此在生成样本时应该保证每个样本都生成了同样多的数目，特别需要注意该脚本可以同时指定多个文件夹，也需要应该保证每个文件夹中生成了同样多的测试样本。

##### 一些可以设置的全局变量

* `log_threshold` 用于指定trace文件的最短长度，小于该长度的trace文件会被认为是无效的



### 一些配置类的脚本

#### InsHexLst.py

用于存放一个指令列表，列表中的指令无法被keystone正确汇编，因此存放在此处

#### suffix.py

用来指定下列几种文件的后缀名

| 文件类型                    | 后缀名   |
| --------------------------- | -------- |
| C源文件                     | .c       |
| 生成的trace文件             | .log     |
| 生成的可执行文件            | .exe     |
| themida混淆后的文件         | .vm.exe  |
| VMProtect混淆后的文件       | .vmp.exe |
| CodeVirtualizer混淆后的文件 | .cv.exe  |
| Enigma混淆后的文件          | .eni.exe |
| Obsidium混淆后的文件        | .obs.exe |



### 其他

* sort.py  对输出文件进行排序，这个脚本主要是为了规范各个文件输出的指令顺序，方便进行比较

