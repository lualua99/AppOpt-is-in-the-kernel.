# AppOpt - 应用CPU优化工具

## 项目简介

AppOpt是一个Linux内核模块，专为Android设备设计，用于优化应用程序的CPU使用。通过为不同应用和线程设置特定的CPU亲和性，AppOpt可以提高系统性能、减少功耗，并优化资源分配。

## 功能特点

### 核心功能

- **应用级CPU亲和性管理**：为特定应用程序设置首选CPU核心
- **线程级CPU亲和性管理**：为应用中的特定线程设置CPU核心偏好
- **完整包名支持**：通过读取/proc文件系统获取完整包名，避免进程名截断问题
- **配置文件驱动**：通过简单的配置文件定义优化规则
- **实时监控与应用**：定期扫描进程并应用配置的规则
- **Proc文件系统接口**：提供状态查询接口

### 技术优势

1. **内核空间实现**：相比用户空间工具，具有更低的开销和更高的权限
2. **完整包名识别**：使用内核API `get_cmdline()` 解决了传统进程名截断（15字符限制）的问题，避免了SELinux权限问题
3. **灵活的规则定义**：支持精确匹配和通配符匹配
4. **优先级机制**：为不同规则设置优先级，确保正确的规则应用顺序
5. **自动配置刷新**：检测配置文件变化并自动重新加载
6. **与KernelSU集成**：通过KernelSU的SELinux规则管理，避免权限问题

## 系统要求

- Linux内核 4.19 或更高版本
- KernelSU 已安装并启用
- Android设备（基于SM8250平台测试）

## 安装方法

### 编译内核模块

1. 将AppOpt源代码放入内核源码树的`drivers/appopt/`目录
2. 确保`drivers/appopt/Kbuild`文件存在且配置正确
3. 在内核配置中启用AppOpt：
   ```bash
   make menuconfig
   # 进入 Device Drivers -> AppOpt
   # 选择 [*] AppOpt - Application CPU Optimizer
   ```
4. 编译内核：
   ```bash
   make -j$(nproc)
   ```
5. 刷入编译好的内核镜像

### 配置文件设置

1. 在设备上创建配置文件：`/data/adb/applist.prop`
2. 按照以下格式添加规则：
   ```
   # 格式：<包名>:<线程名>=<CPU核心范围>
   # 示例1：为整个应用设置CPU亲和性
   com.example.app=0-3
   # 示例2：为应用的特定线程设置CPU亲和性
   com.example.app:MainThread=0-1
   com.example.app:RenderThread=2-3
   # 示例3：使用通配符
   com.example.*=0-2
   ```

## 使用说明

### 配置文件格式

配置文件使用简单的键值对格式：

- **包名**：应用的完整包名，支持通配符（*、?、[]）
- **线程名**：可选，应用中的线程名，支持通配符
- **CPU核心范围**：指定CPU核心，可以是单个核心（如"0"）或范围（如"0-3"）

### 示例配置

```
# 系统应用优化
com.android.systemui=0-1
com.android.launcher3=0-2

# 游戏优化
com.example.game=0-7
com.example.game:GameThread=4-7
com.example.game:RenderThread=2-3

# 后台应用限制
com.example.background=0-1

# 通配符示例
com.example.*=0-3
*:HeavyThread=4-7
```

### 查看状态

通过Proc文件系统查看AppOpt状态：

```bash
cat /proc/appopt/status
```

输出示例：
```
AppOpt Version: 1.0
Running: yes
Check Interval: 2 seconds
Config Path: /data/adb/applist.prop
Loaded Rules: 10
Loaded Packages: 5
Wildcard Rules: 2
```

## SELinux规则配置

### 注意事项

AppOpt本身不包含SELinux规则，而是通过KernelSU的SELinux规则管理系统来获取必要的权限。这是因为：

1. **简化设计**：避免了复杂的SELinux策略管理
2. **更高兼容性**：利用KernelSU成熟的SELinux规则处理机制
3. **更好的安全性**：通过KernelSU的权限管理系统统一处理

### 必需的SELinux规则

开发者需要在KernelSU的SELinux规则文件中添加以下规则，以确保AppOpt正常运行：

**文件路径**：`/home/builder/kernel_xiaomi_sm8250/KernelSU/kernel/selinux/rules.c`

**需要添加的规则**：

```c
// AppOpt rules: allow kernel domain to access config files
ksu_allow(db, "kernel", "adb_data_file", "file", "read");
ksu_allow(db, "kernel", "adb_data_file", "file", "open");
ksu_allow(db, "kernel", "adb_data_file", "file", "getattr");
ksu_allow(db, "kernel", "adb_data_file", "dir", "search");
ksu_allow(db, "kernel", "adb_data_file", "dir", "read");
ksu_allow(db, "kernel", "adb_data_file", "dir", "getattr");

// AppOpt rules: allow kernel domain to set scheduling parameters for processes
ksu_allow(db, "kernel", "system_server", "process", "setsched");
ksu_allow(db, "kernel", "appdomain", "process", "setsched");
ksu_allow(db, "kernel", "untrusted_app", "process", "setsched");
```

### 规则说明

1. **配置文件访问权限**：允许AppOpt读取存储在`/data/adb/`目录中的配置文件
2. **进程调度权限**：允许AppOpt为不同域的进程设置CPU亲和性和调度参数

### 重要说明

- AppOpt 使用内核API `get_cmdline()` 获取完整包名，不再需要访问 `/proc` 文件系统
- 这种实现方式避免了SELinux权限问题，无需为各种进程上下文添加权限
- 内核API直接从进程数据结构中获取信息，更高效且安全

## 工作原理

1. **初始化**：模块加载时创建Proc文件系统接口并启动工作线程
2. **配置加载**：读取并解析配置文件，构建规则列表
3. **进程扫描**：定期扫描系统中的所有进程
4. **包名识别**：使用内核API `get_cmdline()` 获取完整包名，避免SELinux权限问题
5. **规则匹配**：为每个进程和线程匹配适用的规则
6. **亲和性应用**：调用`sched_setaffinity`设置CPU亲和性
7. **状态更新**：更新Proc文件系统中的状态信息

## 性能影响

### 优点

- **减少CPU切换开销**：通过固定线程到特定核心，减少缓存失效
- **优化资源分配**：将重要线程分配给高性能核心
- **降低功耗**：减少不必要的CPU唤醒和切换
- **提高响应速度**：关键应用获得更好的CPU资源

### 注意事项

- 过度限制CPU核心可能导致某些应用性能下降
- 建议根据设备硬件配置和应用特性调整规则
- 定期监控系统性能，根据实际情况优化配置

## 故障排除

### 常见问题

1. **配置不生效**
   - 检查配置文件格式是否正确
   - 确认包名是否与应用的实际包名匹配
   - 查看系统日志是否有相关错误信息

2. **SELinux权限错误**
   - 确认已正确添加KernelSU的SELinux规则
   - 检查系统日志中的SELinux拒绝信息

3. **性能下降**
   - 调整CPU核心分配，避免过度限制
   - 检查是否有冲突的规则

### 日志查看

```bash
# 查看AppOpt相关日志
logcat | grep AppOpt

# 查看SELinux相关日志
logcat | grep avc:
```

## 版本历史

### v1.0
- 初始版本
- 基本应用和线程级CPU亲和性管理
- 完整包名支持
- KernelSU SELinux集成

## 开发者信息

### 模块参数

- `appopt_interval`：检查间隔（秒），默认值：2

### 源码结构

```
drivers/appopt/
├── appopt_core.c     # 核心实现
├── Kbuild            # 构建配置
└── README.md         # 本文档
```

### 编译选项

- `CONFIG_APPOPT`：启用/禁用AppOpt模块

## 贡献指南

欢迎提交问题报告和改进建议。如果您希望贡献代码，请确保：

1. 遵循Linux内核编码风格
2. 保持代码简洁明了
3. 添加适当的注释
4. 测试您的更改

## 免责声明

使用本工具需要谨慎，不当的配置可能导致系统不稳定或性能下降。请在测试环境中充分测试后再应用到生产设备。
