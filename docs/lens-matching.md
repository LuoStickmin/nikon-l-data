# D750 镜头匹配逻辑（L 数据查找函数逆向）

目标：搞清楚相机拿什么键去 NKLD 里选记录，为“加第三方镜头记录（如 Tamron B005）”铺路。

固件：`b1010_115a.bin`（D750 主，基址 `0x90020000`，ARM **Thumb-2**）。
注意：Ghidra 里要先 `clearListing` 再把 `TMode=1`，否则会按 ARM 解码成乱码
（见 `tools-ghidra/DumpThumb.java`）。

## 1. 查找函数 `0x9004D924`

调用点：`0x9004E5FE`、`0x9017E7F2`、`0x9018113A`。

入口：

```
9004D928  mov r4,r0            ; r0 = L 数据状态结构（D750 RAM 0x101E7168）
9004D932  mov r7,r1            ; r1 = lensinfo（镜头信息结构）
9004D952  ldr r6,[r7,#0x34]    ; lensinfo->LensData 指针
```

键的构造（lensinfo 的字节）：

```
r5  = lensinfo[0x11] | (lensinfo[0x22] << 8)     ; 与记录 +2 的 BE u16 比较
r10 = lensinfo[0x1b] | (lensinfo[0x23] << 8)     ; 与记录 +4 的 BE u16 比较
r9  = lensinfo[0x27]，或按 lensinfo[0x18]/[0x1a]/[0x1c] 及镜头类型
      （0x2d/0x31/0x32/0x7b 等分支）换算出来的值 ; 与记录 +7 比较
```

## 2. 逐记录比较（`0x9004DABC` 起）

```
r2 = L 数据基址 + u16 BE(base+0x00)   ; 记录区起点 0x20
r3 = u16 BE(base+0x06)                ; 记录数
循环：
  r6 = BE u16(rec+2)   ; cmp r5
  r7 = BE u16(rec+4)   ; cmp r10
  r1 = rec[7]          ; cmp r9
  r12= rec[8]          ; cmp 标志位 [sp+8]（某些机型/镜头类型为 1）
```

四个键全中才算匹配。

## 3. 命中后的搬运（`0x9004DB00` 起）

把记录前 0x14 字节和 27 个大端词搬进 0x84 字节运行时结构（`r4`）：

- `rec[0..1]`（BE u16）→ 运行时 +0
- `rec[2..3]`（BE u16）→ +2
- `rec[4..5]`（BE u16）→ +4
- `rec[6]`、`rec[7]`、`rec[8]` → +6、+7、+8
- `rec[0xa]` ↔ `+0xf`、`rec[0xb]` ↔ `+0xe`（字节交换）
- `rec[0x14..0x7F]` 的 27 个 BE 词逐字节倒序 → `+0x1b..+0x84`（`0x9004DB40` 的循环）

## 4. 关键结论

- **匹配键不是 8 字节 LensID**，而是来自运行时 `lensinfo` 结构的字节
  `0x11/0x22/0x1b/0x23/0x27`（以及 `0x18/0x1a/0x1c` 的换算）。
- `lensinfo` 在 EXIF 上下文结构里，偏移 `+0x2C5C`（见 `0x9017E7E0`：
  `movw r0,#0x2c5c; add r1,r4,r0; bl 0x9004d924`）。
- NEF 里能拿到的 LensData 只有 33 字节（解密后以 `0204` 开头），而 `lensinfo`
  用到的 `0x22/0x23/0x27` 已经超出这 33 字节——**说明它是相机运行时从镜头 CPU
  读到的更长结构，NEF 存不下**。

## 5. lensinfo 的填充函数（`0x900C6C72`）

找到了往 `ctx+0x2C5C` 填字段的函数（`0x900C6C72` 起）：

```
r1 = [0x900C6D94]      ; 全局对象指针
r1 = [r1+0]            ; 对象
r3 = [r1+0xc]          ; 源结构（相机内部的 lens data）
```

然后逐字节拷贝，映射如下（`dest = lensinfo[ctx+0x2C5C]`，`src = 源结构`）：

```
dest[0x00..0x0f] <- src[0x00..0x0f]
dest[0x10] <- src[0x11]
dest[0x11] <- src[0x14]      ; ← 匹配键 r5 的低字节
dest[0x12] <- src[0x15]
dest[0x13] <- src[0x16]
dest[0x14] <- src[0x17]
dest[0x15] <- src[0x18]
dest[0x16] <- src[0x19]
dest[0x17] <- src[0x1a]
dest[0x18] <- src[0x1b]
dest[0x19] <- src[0x1c]
dest[0x1a] <- src[0x1d]
dest[0x1b] <- src[0x1e]      ; ← 匹配键 r10 的低字节
dest[0x1c] <- src[0x1f]
dest[0x1d] <- src[0x20]
dest[0x1e] <- src[0x21]
dest[0x1f] <- src[0x22]
dest[0x20] <- src[0x23]
dest[0x21] <- src[0x24]
dest[0x22] <- src[0x25]      ; ← 匹配键 r5 的高字节
dest[0x23] <- src[0x26]      ; ← 匹配键 r10 的高字节
dest[0x24] <- src[0x2f]
dest[0x25] <- src[0x30]
dest[0x26] <- src[0x31]
dest[0x27] <- src[0x32]      ; ← 匹配键 r9
```

即匹配用的四个键（按记录 `+2/+4/+7/+8`）分别来自源结构的：

```
rec+2 (BE u16) = src[0x14] | src[0x25]<<8
rec+4 (BE u16) = src[0x1e] | src[0x26]<<8
rec[7]         = src[0x32]（或由 src[0x1b]/[0x1d]/[0x1f] 换算）
rec[8]         = 标志字节
```

## 6. 卡点：源结构不在 NEF 里

- NEF 的 LensData（tag 0x0098）解密后只有 33 字节（`0x00..0x20`），而键需要
  `src[0x25]/[0x26]/[0x32]`——**超出了 NEF 能提供的范围**；
- 在 B005 的 NEF 里搜过 LensID 明文、LensData 头部明文：都没有，说明完整结构
  只存在于相机运行时内存（从镜头 CPU 读出来的更长结构）。
- 因此静态路线要再往下走一层：找这个“源结构”的填充代码（镜头通信/解析路径），
  或者用实时相机（PTP）把 lensinfo 读出来。

## 7. 下一步

1. 找源结构的填充函数（从 `[0x900C6D94]` 这个对象出发，或镜头通信模块里写
   `+0x14/+0x1e/+0x25/+0x26/+0x32` 的代码）；
2. 有映射后即可为任意镜头（B005、18-200）算出记录键；
3. 系数侧仍需 B005 的畸变标定数据，用来定 XOR 密钥的符号方向。
