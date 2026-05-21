#pragma once

#include <Windows.h>
#include <QString>
#include <QWidget>

/**
 * @brief 动态提权辅助工具
 *
 * 设计思路：GUI 主进程始终以普通用户权限运行。
 * 当需要管理员权限执行操作时，启动一个独立的 "提权代理" 子进程
 * (MardukElevated.exe) 以 runas 方式运行，该子进程执行完特定命令后退出。
 *
 * 这样做的优势：
 * 1. GUI 永远不需要以管理员身份运行 — 用户体验好
 * 2. UAC 弹窗只在真正需要时才出现 — 精确控制
 * 3. 如果用户取消 UAC 弹窗，GUI 仍然正常工作 — 优雅降级
 * 4. 提权进程执行完即退出 — 最小权限暴露
 *
 * 子进程通信方式：
 * - 输入：命令行参数指定操作
 * - 输出：进程退出码（0=成功, 非0=失败）
 * - 详细结果：通过临时文件传递（可选）
 */
class ElevationHelper
{
public:
    /**
     * @brief 检查当前进程是否以管理员身份运行
     */
    static bool isRunningAsAdmin();

    /**
     * @brief 以管理员权限运行提权代理子进程
     *
     * @param arguments 传给 MardukElevated.exe 的命令行参数
     * @param parent    父 Widget（用于 UAC 弹窗的窗口句柄关联）
     * @return true     子进程成功执行并返回 0
     * @return false    用户取消 UAC / 启动失败 / 子进程返回非 0
     */
    static bool runElevated(const QString& arguments, QWidget* parent = nullptr);

    /**
     * @brief 以管理员权限运行提权代理，并获取子进程的退出码
     *
     * @param arguments     命令行参数
     * @param exitCode      [out] 子进程退出码
     * @param parent        父 Widget
     * @return true         子进程成功启动并执行完毕
     * @return false        UAC 被取消或启动失败
     */
    static bool runElevatedWithExitCode(const QString& arguments,
                                        DWORD& exitCode,
                                        QWidget* parent = nullptr);

    /**
     * @brief 获取提权代理进程的路径
     *
     * 默认在与 MardukGui.exe 同目录下查找 MardukElevated.exe
     */
    static QString getElevatedHelperPath();

private:
    ElevationHelper() = default;
};
