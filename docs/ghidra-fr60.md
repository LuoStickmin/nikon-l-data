# Ghidra 12 + FR60 环境与 D90 Firmware A 初读

## 1. 环境

- Ghidra 12.2 PUBLIC（用户提供 zip，SHA-256 `2c2cd776…a7be67`，与官方发布页一致）
- Microsoft OpenJDK 25（Ghidra 12.2 要求 JDK 25+；JDK 21 会被拒绝）
- FR60 语言来自 `desrdev/ghidra-fr60`（Apache-2.0），只用其中的 Sleigh 语言文件，没装完整插件

Ghidra 自带 `support/sleigh`，可以直接把 `.slaspec` 编译成 `.sla`：

```bash
support/sleigh.bat <repo>/data/languages/fr60.slaspec   # 产出 fr60.sla
```

然后把 `fr60.ldefs / fr60.pspec / fr60.cspec / fr60.sinc / fr60.sla` 等复制到
`Ghidra/Processors/FR60/data/languages/`，并放一个空的 `Module.manifest`。启动后语言 ID 为
`fr60:BE:16:default`（16 是 ID 字段，实际地址空间按 `fr60.slaspec` 的 32 位 ram space）。

**本机遇到的坑**：

- Ghidra 的 `LaunchSupport` 会往 `%APPDATA%`、`%TEMP%` 写 `java_home.save`/临时目录，而当前
  沙箱对这两个目录写入被拒；把 `APPDATA`、`TEMP`、`TMP` 三个环境变量重定向到工作区目录即可。
- `-import` 的工程路径不能含以 `.` 开头的路径段，否则报 “Path element starting with '.' is not
  permitted”。把工程放在 `ghidra-work/` 这类目录下。

## 2. 已验证：D90 代码是 FR60，且能干净反汇编

用 `analyzeHeadless + BinaryLoader + fr60:BE:16:default` 导入 `D90_0101.bin`，线性反汇编
`0x169474`、`0x1ACF80` 等位置，得到的是正常的 FR60 指令（`LDI:8/20/32`、`LDUH`、`STH`、
`ENTER/LEAVE`、`CALL:D` 等），不再是 ARM/FR30 的乱码。**此前的 FR30/FR-V 失败是因为 ISA 不对，
不是代码加密/压缩。**

## 3. L 数据头校验函数（0x1ACF48 内）

```text
1ACF9E  LDI:8  #8,AC
1ACFA0  LD     @(AC,R8),R0        ; header+8
1ACFA2  LDI:32 #0x87c7caac,R1     ; NKLD/WMA 容器魔数
1ACFA8  CMP    R1,R0
1ACFAA  BNE    fail               ; 魔数不符 -> 失败
1ACFAC  ...
1ACFB0  ADD    #4,R4              ; header+4 = 版本
1ACFB2  LDUB   @R4,R0
1ACFB4  CMP    #1,R0              ; 接受版本主字节 1 或 2
1ACFBC  LDUB   @R4,R0
1ACFBE  CMP    #2,R0
...
1ACFD2  LDI:8  #0xc,AC
1ACFD4  LDUH   @R8,R0             ; header+0
1ACFD6  LDUH   @(AC,R8),R1        ; header+0xc
1ACFD8  ADD    R1,R0
1ACFEE  LD     @R10,R0
1ACFF0  LDI:20 #0x20000,R1
1ACFF4  CMP    R1,R0
1ACFF6  BLS    ok                 ; 数据长度 <= 0x20000
```

结论：D90 的 A 固件里确实有 L 数据容器的**头校验**，但没看到对 27 个系数词做 XOR 的循环；
它更像“升级时校验 + 写 flash”的路径。

## 4. 文件类型表与入口

`0x213000` 是 9 个 32 位指针（`段:偏移` 形式的 BE 地址）：

```
0x0016799E 0x001679A8 0x001679B2 0x001679BC
0x00169474 0x0016947C 0x00169484 0x0016948C 0x00169494
```

紧随其后是文件名模板：`S ---.---`、`NKLD????.BIN`（`0x21305E`）、`S???????.BIN`、
`D90_????.BIN`、`BD90????.BIN`、`AD90????.BIN`。

`0x169474` 处的 handler 是 FR60 代码，做文件名/字节串比较并调用 `0x11DC58`、`0x11DCD4`、
`0x129680` 等函数；目前还没定位到它与 L 数据解析的直接关系。

## 5. 关键判断

`D90_0101.bin` 的头部写明 **“D90 Firmware A”**，镜像里没有 “Firmware B” 字符串。A 固件是
升级/引导部分；真正使用 27 个系数词做畸变校正的是 **B 固件（主固件）**，而这次拿到的升级包里
只有 A。

因此：

- D90 的 A 固件能告诉我们 L 数据文件是怎么被**校验**和**写入 flash** 的；
- 但**解混淆（如果确实存在）很可能在 B 固件里**，或者根本不存在——即相机直接把文件写进 flash，
  运行时读低 16 位系数；
- 继续在 A 里找 XOR 循环的收益有限，下一步更应该找 B 固件镜像（或确认 A 镜像里是否还嵌着 B 的
  压缩块，例如 `0x5C0000` 附近那段高熵数据）。

## 6. 复现

```bash
# 语言编译 + 安装（见第 1 节）
# 导入 + 反汇编
analyzeHeadless.bat ghidra-work/proj D90full \
  -import ghidra-work/D90_0101.bin \
  -processor fr60:BE:16:default -loader BinaryLoader \
  -noanalysis -scriptPath tools-ghidra \
  -postScript DumpRange.java 0x1ACF80 0x120
```

`tools-ghidra/DumpRange.java`、`DumpRefs.java` 在仓库里。
