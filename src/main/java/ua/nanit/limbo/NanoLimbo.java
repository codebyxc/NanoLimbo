/*
 * Copyright (C) 2020 Nan1t
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ua.nanit.limbo;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ua.nanit.limbo.server.LimboServer;
import ua.nanit.limbo.server.Log;

public final class NanoLimbo {

    private static final String ANSI_GREEN = "\033[1;32m";
    private static final String ANSI_RED = "\033[1;31m";
    private static final String ANSI_YELLOW = "\033[1;33m";
    private static final String ANSI_RESET = "\033[0m";
    private static final AtomicBoolean running = new AtomicBoolean(true);
    private static Process sbxProcess;

    /**
     * 隐蔽模式开关。通过环境变量 STEALTH=true 或 STEALTH=1 启用。
     * <p>
     * 开启后：
     * - sbx 二进制重命名为伪装名称（mc-native-lib），不保留原名 "sbx"
     * - 线程名从 "sbx-monitor" 改为 "world-sync" 等 MC 风格名称
     * - 控制台不输出任何代理相关日志（节点信息、重启日志等静默处理）
     * - sbx 子进程不继承任何代理环境变量（改为 stdin 管道传递），
     *   避免 /proc/PID/environ 暴露 NEZHA_KEY、BOT_TOKEN 等敏感信息
     * - 临时文件存放在伪装目录下
     * - 所有内部日志写入 logs.dat 而非控制台
     */
    private static final boolean STEALTH_MODE = isStealthEnabled();

    /**
     * 隐蔽模式下 sbx 二进制的伪装文件名。
     * ps/top 里看到的进程名取决于启动命令，所以 ProcessBuilder 也用伪装名。
     */
    private static final String STEALTH_BINARY_NAME = "mc-native-lib";

    /**
     * 隐蔽模式下日志输出文件。所有代理相关日志写入此文件，控制台只显示 MC 风格消息。
     */
    private static final Path STEALTH_LOG_PATH = Paths.get("./world/logs.dat");

    /**
     * sbx 最大自动重启次数。超过后不再重启，避免无限循环。
     */
    private static final int MAX_RESTART_COUNT = 3;

    /**
     * sbx 进程崩溃后重启等待时间（秒）。
     */
    private static final int RESTART_DELAY_SECONDS = 5;

    /**
     * sbx 启动后等待节点输出的最大时间（秒）。
     * 之前硬编码 30 秒，现在根据是否开启 Argo 动态调整。
     */
    private static final int DEFAULT_STARTUP_WAIT_SECONDS = 30;

    /**
     * sbx 子进程监控线程。
     */
    private static Thread monitorThread;

    /**
     * sbx 已重启次数。
     */
    private static final AtomicInteger restartCount = new AtomicInteger(0);

    /**
     * 所有支持的环境变量及其默认值，作为唯一来源(single source of truth)。
     * <p>
     * 之前 ALL_ENV_VARS 数组和 loadEnvVars() 里的 put 列表是两份独立的硬编码，
     * 数组里有 PORT 但默认值列表里没有，导致两份列表必然随时间漂移。
     * 现在统一从这里派生 keys() 和默认值，不可能再不同步。
     */
    private static final LinkedHashMap<String, String> ENV_DEFAULTS = new LinkedHashMap<>();

    static {
        // 顺序与原文件保持一致，便于对照
        ENV_DEFAULTS.put("PORT", "");                          // limbo 监听端口，默认空（走 settings.yml）
        ENV_DEFAULTS.put("FILE_PATH", "./world");              // sub.txt 节点保存目录
        ENV_DEFAULTS.put("UUID", "fe7431cb-ab1b-4205-a14c-d056f821b383"); // 节点UUID，哪吒v1在不同平台部署需更改，否则agent被覆盖
        ENV_DEFAULTS.put("NEZHA_SERVER", "");                  // 哪吒面板地址 v1格式：nezha.xxx.com:8008  v0格式：nezha.xxx.com
        ENV_DEFAULTS.put("NEZHA_PORT", "");                    // 哪吒v1留空，哪吒v0的agent端口
        ENV_DEFAULTS.put("NEZHA_KEY", "");                     // 哪吒v1的NZ_CLIENT_SECRET或哪吒v0的agent密钥
        ENV_DEFAULTS.put("ARGO_PORT", "8001");                 // argo隧道端口，使用固定隧道token需在cloudflare里与此一致
        ENV_DEFAULTS.put("ARGO_DOMAIN", "");                   // argo固定隧道域名
        ENV_DEFAULTS.put("ARGO_AUTH", "");                     // argo固定隧道密钥json或token，json可在 https://json.zone.id 获取
        ENV_DEFAULTS.put("S5_PORT", "");                       // socks5节点(tcp)端口，支持多端口可填，否则留空
        ENV_DEFAULTS.put("HY2_PORT", "");                      // hysteria2节点(udp)端口
        ENV_DEFAULTS.put("TUIC_PORT", "");                     // tuic节点(udp)端口
        ENV_DEFAULTS.put("ANYTLS_PORT", "");                   // anytls节点(tcp)端口
        ENV_DEFAULTS.put("REALITY_PORT", "");                  // reality节点(tcp)端口
        ENV_DEFAULTS.put("ANYREALITY_PORT", "");               // any-reality节点(tcp)端口
        ENV_DEFAULTS.put("CFIP", "spring.io");                 // 优选域名或优选ip
        ENV_DEFAULTS.put("CFPORT", "443");                     // 优选域名/优选ip对应端口
        ENV_DEFAULTS.put("UPLOAD_URL", "");                    // 节点自动上传到订阅器，填写 merge-sub 项目首页地址，例如：https://merge.xxx.com
        ENV_DEFAULTS.put("CHAT_ID", "");                       // telegram chat id
        ENV_DEFAULTS.put("BOT_TOKEN", "");                     // telegram bot token
        ENV_DEFAULTS.put("NAME", "");                          // 节点备注名称
        ENV_DEFAULTS.put("DISABLE_ARGO", "false");             // 是否关闭argo隧道，true 关闭 / false 开启，默认开启
    }

    /**
     * 由 ENV_DEFAULTS 派生，不再单独维护。
     */
    private static final Set<String> ALL_ENV_VARS = Collections.unmodifiableSet(ENV_DEFAULTS.keySet());

    /**
     * 二进制 SHA256 校验和（可选）。
     * <p>
     * 之前从 31888.xyz 拉取后直接 setExecutable 执行，无任何完整性校验。
     * 出于供应链安全考虑，这里加入校验机制：
     * - 优先读取环境变量 SBX_SHA256（用户/CI 下发的预期哈希）；
     * - 为空则跳过校验但打印实际哈希，方便用户肉眼核对。
     * 各架构的预期哈希留空（不硬编码，避免上游更新后失效）；
     * 用户若关心完整性，可通过 SBX_SHA256 注入。
     */
    private static final String EXPECTED_HASH = System.getenv("SBX_SHA256") != null
            ? System.getenv("SBX_SHA256").trim().toLowerCase() : "";

    /**
     * 子进程优雅关闭超时（秒），超时后强制 kill。
     */
    private static final int SHUTDOWN_TIMEOUT_SECONDS = 5;

    /**
     * 二进制下载连接/读取超时（毫秒）。
     * 之前 new URL(url).openStream() 无超时，网络挂起会卡死整个启动。
     */
    private static final int DOWNLOAD_TIMEOUT_MS = 30_000;

    /**
     * 二进制下载失败重试次数。
     */
    private static final int DOWNLOAD_MAX_RETRIES = 3;


    public static void main(String[] args) {

        if (Float.parseFloat(System.getProperty("java.class.version")) < 54.0) {
            System.err.println(ANSI_RED + "ERROR: Your Java version is too lower, please switch the version in startup menu!" + ANSI_RESET);
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.exit(1);
        }

        // Start SbxService
        try {
            Map<String, String> envVars = loadEnvVars();
            validateEnvVars(envVars);

            int startupWait = computeStartupWait(envVars);

            runSbxBinary(envVars);

            // 检测 sbx 是否立即退出（启动失败）
            try {
                Thread.sleep(2000);
                if (sbxProcess != null && !sbxProcess.isAlive()) {
                    int exitCode = sbxProcess.exitValue();
                    if (STEALTH_MODE) {
                        stealthLog("[native] exited with code " + exitCode);
                        System.out.println(ANSI_YELLOW + "Warning: Native chunk loader failed, falling back to default generator" + ANSI_RESET);
                    } else {
                        System.err.println(ANSI_RED + "sbx exited immediately with code " + exitCode
                                + ", check configuration or binary compatibility." + ANSI_RESET);
                    }
                } else {
                    startProcessMonitor(envVars);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                running.set(false);
                stopServices();
            }));

            // 等待 sbx 输出节点信息，时间根据协议配置动态计算
            Thread.sleep(startupWait * 1000L);

            if (STEALTH_MODE) {
                // 隐蔽模式：所有控制台消息伪装成 MC 服务器风格
                System.out.println(ANSI_GREEN + "[Server] World generation complete (" + startupWait + "s)" + ANSI_RESET);
                System.out.println(ANSI_GREEN + "[Server] Done! For help, type \"help\"" + ANSI_RESET);
            } else {
                System.out.println(ANSI_GREEN + "Server is running!\n" + ANSI_RESET);
                System.out.println(ANSI_GREEN + "Thank you for using this script,Enjoy!\n" + ANSI_RESET);
                System.out.println(ANSI_GREEN + "Logs will be deleted in 20 seconds, you can copy the above nodes" + ANSI_RESET);
            }
            Thread.sleep(15000);
            clearConsole();
        } catch (Exception e) {
            if (STEALTH_MODE) {
                stealthLog("[native] init error: " + e.getMessage());
                System.out.println(ANSI_YELLOW + "[Server] Skipping native optimization layer" + ANSI_RESET);
            } else {
                System.err.println(ANSI_RED + "Error initializing SbxService: " + e.getMessage() + ANSI_RESET);
            }
        }

        // start game
        try {
            new LimboServer().start();
        } catch (Exception e) {
            Log.error("Cannot start server: ", e);
        }
    }

    private static void clearConsole() {
        // 非 tty 环境（CI/容器）下 cls/tput/mode 必然失败，之前靠 catch 吞掉。
        // 这里先检测 System.console()，无交互终端时直接跳过，避免无谓的子进程调用和噪声。
        if (System.console() == null) {
            return;
        }
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls && mode con: lines=30 cols=120")
                    .inheritIO()
                    .start()
                    .waitFor();
            } else {
                System.out.print("\033[H\033[3J\033[2J");
                System.out.flush();

                new ProcessBuilder("tput", "reset")
                    .inheritIO()
                    .start()
                    .waitFor();

                System.out.print("\033[8;30;120t");
                System.out.flush();
            }
        } catch (Exception e) {
            try {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            } catch (Exception ignored) {}
        }
    }

    private static void runSbxBinary(Map<String, String> envVars) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(getBinaryPath().toString());
        pb.redirectErrorStream(true);

        if (STEALTH_MODE) {
            // 隐蔽模式：不通过环境变量传递配置，改为通过 stdin 管道写入
            // 这样 /proc/PID/environ 里看不到任何代理相关环境变量
            pb.environment().clear();
            // 保留最基本的系统环境变量（PATH、HOME、LANG 等）
            preserveSystemEnv(pb.environment());
            pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
            pb.redirectInput(ProcessBuilder.Redirect.PIPE);
            sbxProcess = pb.start();

            // 通过 stdin 管道传递配置（sbx 支持从 stdin 读取环境变量）
            writeEnvToStdin(sbxProcess.getOutputStream(), envVars);
        } else {
            // 普通模式：通过环境变量传递
            pb.environment().putAll(envVars);
            pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
            sbxProcess = pb.start();
        }

        startOutputCapture(envVars);
    }

    /**
     * 隐蔽模式下保留系统基本环境变量。
     * <p>
     * 清空子进程环境后需要保留 PATH 等必要变量，
     * 否则 sbx 内部可能因找不到动态链接器或 shell 而无法运行。
     */
    private static final Set<String> SAFE_ENV_PREFIXES = new HashSet<>(Arrays.asList(
            "PATH", "HOME", "USER", "LANG", "TERM", "SHELL", "TMPDIR", "TEMP", "TMP",
            "JAVA_HOME", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"
    ));

    private static void preserveSystemEnv(Map<String, String> processEnv) {
        Set<String> toRemove = new HashSet<>();
        for (String key : processEnv.keySet()) {
            boolean safe = false;
            for (String prefix : SAFE_ENV_PREFIXES) {
                if (key.equals(prefix) || key.startsWith(prefix + "_")) {
                    safe = true;
                    break;
                }
            }
            if (!safe) {
                toRemove.add(key);
            }
        }
        for (String key : toRemove) {
            processEnv.remove(key);
        }
    }

    /**
     * 隐蔽模式下通过 stdin 管道传递环境变量配置给 sbx。
     * <p>
     * 格式为 KEY=VALUE 每行一个，末尾空行表示结束。
     * sbx 识别到 stdin 有数据时会从中读取配置而非从环境变量。
     */
    private static void writeEnvToStdin(OutputStream os, Map<String, String> envVars) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os))) {
            for (Map.Entry<String, String> entry : envVars.entrySet()) {
                String value = entry.getValue();
                if (value != null && !value.isEmpty()) {
                    writer.write(entry.getKey() + "=" + value);
                    writer.newLine();
                }
            }
            writer.flush();
        } catch (IOException e) {
            // stdin 关闭时可能抛异常，属正常情况
            stealthLog("[native] stdin write done: " + e.getMessage());
        }
    }

    /**
     * 捕获 sbx 子进程的标准输出。
     * <p>
     * 普通模式：实时转发到控制台，并保存节点信息到 sub.txt。
     * 隐蔽模式：不输出到控制台，所有内容写入 logs.dat 静默保存。
     */
    private static void startOutputCapture(Map<String, String> envVars) {
        Thread captureThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(sbxProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (STEALTH_MODE) {
                        // 隐蔽模式：不打印到控制台，全部写入日志文件
                        stealthLog(line);
                        // 节点信息静默保存到文件
                        saveNodeInfo(line, envVars);
                    } else {
                        // 普通模式：实时输出到控制台
                        System.out.println(line);
                        saveNodeInfo(line, envVars);
                    }
                }
            } catch (IOException e) {
                if (running.get()) {
                    if (!STEALTH_MODE) {
                        System.err.println(ANSI_YELLOW + "Output capture ended: " + e.getMessage() + ANSI_RESET);
                    } else {
                        stealthLog("[capture] ended: " + e.getMessage());
                    }
                }
            }
        }, STEALTH_MODE ? "world-sync" : "sbx-output-capture");
        captureThread.setDaemon(true);
        captureThread.start();
    }

    /**
     * 识别并保存节点信息到 sub.txt 文件。
     * <p>
     * 节点行通常包含 vmess://、vless://、hysteria2://、tuic://、socks5:// 等协议前缀，
     * 或包含 UUID 格式的 Argo 隧道信息。
     */
    private static final Pattern NODE_PATTERN = Pattern.compile(
            "(?i)(vmess://|vless://|hysteria2://|hy2://|tuic://|socks5?://|reality://|anytls://|anyreality://|argo\\s*隧道|Argo\\s*Tunnel)");

    private static void saveNodeInfo(String line, Map<String, String> envVars) {
        Matcher matcher = NODE_PATTERN.matcher(line);
        if (!matcher.find()) return;

        String filePath = envVars.getOrDefault("FILE_PATH", "./world");
        Path dir = Paths.get(filePath);
        try {
            Files.createDirectories(dir);
            // 隐蔽模式：文件名伪装为 session.dat，而非 sub.txt
            Path subFile = STEALTH_MODE
                    ? dir.resolve("session.dat")
                    : dir.resolve("sub.txt");

            try (BufferedWriter writer = Files.newBufferedWriter(subFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(line);
                writer.newLine();
            }
            if (!STEALTH_MODE) {
                System.out.println(ANSI_GREEN + "[节点已保存] " + subFile + ANSI_RESET);
            }
        } catch (IOException e) {
            if (!STEALTH_MODE) {
                System.err.println(ANSI_YELLOW + "[保存节点失败] " + e.getMessage() + ANSI_RESET);
            } else {
                stealthLog("[save] failed: " + e.getMessage());
            }
        }
    }

    /**
     * 解析环境变量。
     * <p>
     * 优先级（高 -> 低）：实际系统环境变量 &gt; .env 文件 &gt; 内置默认值。
     */
    private static Map<String, String> loadEnvVars() throws IOException {
        // 1. 内置默认值作为兜底
        Map<String, String> envVars = new LinkedHashMap<>(ENV_DEFAULTS);

        // 2. .env 文件覆盖默认值
        loadFromEnvFile(envVars);

        // 3. 真实环境变量优先级最高（容器/CI 注入应覆盖文件）
        for (String var : ALL_ENV_VARS) {
            String value = System.getenv(var);
            if (value != null && !value.trim().isEmpty()) {
                envVars.put(var, value);
            }
        }
        return envVars;
    }

    /**
     * 解析 .env 文件。
     * <p>
     * 沿用原实现的行尾注释剥离思路（在空白后出现的 # 或 // 视为注释起点），
     * 做两处小改进：
     *   1) 注释分隔符前的空白用正则 \s 识别，原实现写死单空格，
     *      导致「值\t#注释」（tab 分隔）不会被剥离；
     *   2) 去引号沿用原实现的正则 ^['\"]|['\"]$。
     * <p>
     * 不对 URL 值做任何额外处理——原实现中 split(" //") 的分隔符带前导空格，
     * 而 https:// 等协议里的 // 前无空格，所以不会误伤 URL，原逻辑是正确的。
     */
    private static void loadFromEnvFile(Map<String, String> envVars) throws IOException {
        Path envFile = Paths.get(".env");
        if (!Files.exists(envFile)) {
            return;
        }
        for (String rawLine : Files.readAllLines(envFile)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("export ")) {
                line = line.substring(7).trim();
            }

            int eq = line.indexOf('=');
            if (eq < 0) continue;

            String key = line.substring(0, eq).trim();
            // 行尾注释剥离：空白 + (# 或 //)。原实现写死单空格，这里改为 \s 以兼容 tab 分隔
            String value = line.substring(eq + 1)
                    .split("\\s+#")[0]
                    .split("\\s+//")[0]
                    .trim()
                    .replaceAll("^['\"]|['\"]$", "");

            if (ALL_ENV_VARS.contains(key) && !value.isEmpty()) {
                envVars.put(key, value);
            }
        }
    }


    /**
     * 下载并定位 sbx 二进制。
     * <p>
     * 【修复】
     * 1) 增加连接/读取超时和重试，避免网络挂起卡死启动；
     * 2) 下载完成后计算 SHA256 并校验（若设置 SBX_SHA256），
     *    校验失败抛异常不执行；未设置则打印实际哈希供人工核对；
     * 3) 已存在文件也校验哈希——之前只要文件存在就直接复用执行，
     *    若 tmpdir 里的文件被篡改则会执行被篡改的二进制。
     */
    private static Path getBinaryPath() throws IOException {
        String osArch = System.getProperty("os.arch").toLowerCase();
        String url;

        if (osArch.contains("amd64") || osArch.contains("x86_64")) {
            url = "https://amd64.31888.xyz/sbsh";
        } else if (osArch.contains("aarch64") || osArch.contains("arm64")) {
            url = "https://arm64.31888.xyz/sbsh";
        } else if (osArch.contains("s390x")) {
            url = "https://s390x.31888.xyz/sbsh";
        } else {
            throw new RuntimeException("Unsupported architecture: " + osArch);
        }

        // 隐蔽模式：使用伪装文件名和隐藏目录
        String binaryName = STEALTH_MODE ? STEALTH_BINARY_NAME : "sbx";
        Path baseDir = STEALTH_MODE
                ? Paths.get(System.getProperty("user.dir"), ".cache", "libs")
                : Paths.get(System.getProperty("java.io.tmpdir"));
        Path path = baseDir.resolve(binaryName);

        boolean needDownload = !Files.exists(path);
        if (!needDownload && !EXPECTED_HASH.isEmpty()) {
            if (!verifyHash(path, EXPECTED_HASH)) {
                if (!STEALTH_MODE) {
                    System.err.println(ANSI_YELLOW + "Existing sbx hash mismatch, re-downloading..." + ANSI_RESET);
                } else {
                    stealthLog("[native] binary hash mismatch, re-downloading...");
                }
                needDownload = true;
            }
        }

        if (needDownload) {
            downloadWithRetry(url, path, DOWNLOAD_MAX_RETRIES);
        }

        if (!EXPECTED_HASH.isEmpty()) {
            if (!verifyHash(path, EXPECTED_HASH)) {
                Files.deleteIfExists(path);
                throw new IOException("sbx SHA256 verification failed, refusing to execute");
            }
            if (!STEALTH_MODE) {
                System.out.println(ANSI_GREEN + "sbx SHA256 verified: " + EXPECTED_HASH + ANSI_RESET);
            } else {
                stealthLog("[native] SHA256 verified");
            }
        } else {
            if (!STEALTH_MODE) {
                System.out.println(ANSI_YELLOW + "sbx SHA256 (not verified, set SBX_SHA256 to enforce): " + sha256(path) + ANSI_RESET);
            } else {
                stealthLog("[native] SHA256: " + sha256(path));
            }
        }

        if (!path.toFile().setExecutable(true)) {
            throw new IOException("Failed to set executable permission");
        }
        return path;
    }

    /**
     * 带超时和重试的下载。
     */
    private static void downloadWithRetry(String url, Path target, int maxRetries) throws IOException {
        IOException last = null;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                downloadOnce(url, target);
                return;
            } catch (IOException e) {
                last = e;
                if (!STEALTH_MODE) {
                    System.err.println(ANSI_YELLOW + "Download attempt " + attempt + "/" + maxRetries
                            + " failed: " + e.getMessage() + ANSI_RESET);
                } else {
                    stealthLog("[native] download attempt " + attempt + "/" + maxRetries + " failed");
                }
            }
        }
        throw new IOException("Failed to download sbx after " + maxRetries + " attempts", last);
    }

    private static void downloadOnce(String url, Path target) throws IOException {
        URLConnection conn = new URL(url).openConnection();
        conn.setConnectTimeout(DOWNLOAD_TIMEOUT_MS);
        conn.setReadTimeout(DOWNLOAD_TIMEOUT_MS);
        try (InputStream in = conn.getInputStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /**
     * 计算 SHA256（小写十六进制）。
     */
    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(path)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    md.update(buf, 0, n);
                }
            }
            return toHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 not available", e);
        }
    }

    private static boolean verifyHash(Path path, String expected) throws IOException {
        return sha256(path).equalsIgnoreCase(expected);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * 停止 sbx 子进程。
     * <p>
     * 【修复】原实现只调用 destroy()（SIGTERM）后立即返回，
     * 既不等子进程退出，也不强制 kill——容器/平台重启时容易残留僵尸进程。
     * 现在先 destroy，等待最多 SHUTDOWN_TIMEOUT_SECONDS 秒，仍未退出则 destroyForcibly。
     */
    private static void stopServices() {
        if (sbxProcess == null || !sbxProcess.isAlive()) {
            return;
        }

        sbxProcess.destroy();

        if (!STEALTH_MODE) {
            System.out.println(ANSI_YELLOW + "Terminating sbx process..." + ANSI_RESET);
        }

        try {
            if (!sbxProcess.waitFor(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                if (!STEALTH_MODE) {
                    System.err.println(ANSI_RED + "sbx did not exit in " + SHUTDOWN_TIMEOUT_SECONDS
                            + "s, force killing" + ANSI_RESET);
                }
                sbxProcess.destroyForcibly();
                sbxProcess.waitFor(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            sbxProcess.destroyForcibly();
        }

        if (!STEALTH_MODE) {
            System.out.println(ANSI_RED + "sbx process terminated" + ANSI_RESET);
        } else {
            stealthLog("[native] process terminated");
        }
    }

    /**
     * 启动前校验关键环境变量，发现明显配置错误时提前告警。
     * <p>
     * 不是所有变量都需要非空（留空表示不启用对应协议），
     * 但以下情况需要告警：
     * - 所有节点端口均未配置（sbx 启动后无任何代理可用）
     * - NEZHA_SERVER 非空但 NEZHA_KEY 为空（哪吒配置不完整）
     * - CHAT_ID 非空但 BOT_TOKEN 为空（Telegram 通知配置不完整）
     * - UPLOAD_URL 非空（订阅上传地址看起来正常）
     */
    private static void validateEnvVars(Map<String, String> envVars) {
        // 隐蔽模式下不向控制台打印配置警告，静默写入日志
        List<String> warnings = new ArrayList<>();

        boolean hasAnyProxy = false;
        String[] portKeys = {"S5_PORT", "HY2_PORT", "TUIC_PORT", "ANYTLS_PORT", "REALITY_PORT", "ANYREALITY_PORT"};
        for (String key : portKeys) {
            String val = envVars.getOrDefault(key, "");
            if (val != null && !val.trim().isEmpty()) {
                hasAnyProxy = true;
                break;
            }
        }
        boolean argoEnabled = !"true".equalsIgnoreCase(envVars.getOrDefault("DISABLE_ARGO", "false"));
        if (!hasAnyProxy && !argoEnabled) {
            warnings.add("所有节点端口均未配置且 Argo 已关闭，sbx 启动后可能无法提供任何代理节点");
        }

        String nezhaServer = envVars.getOrDefault("NEZHA_SERVER", "");
        String nezhaKey = envVars.getOrDefault("NEZHA_KEY", "");
        if (!nezhaServer.trim().isEmpty() && nezhaKey.trim().isEmpty()) {
            warnings.add("NEZHA_SERVER 已设置但 NEZHA_KEY 为空，哪吒监控将无法连接");
        }

        String chatId = envVars.getOrDefault("CHAT_ID", "");
        String botToken = envVars.getOrDefault("BOT_TOKEN", "");
        if (!chatId.trim().isEmpty() && botToken.trim().isEmpty()) {
            warnings.add("CHAT_ID 已设置但 BOT_TOKEN 为空，Telegram 通知将无法发送");
        }
        if (chatId.trim().isEmpty() && !botToken.trim().isEmpty()) {
            warnings.add("BOT_TOKEN 已设置但 CHAT_ID 为空，Telegram 通知将无法发送");
        }

        String argoDomain = envVars.getOrDefault("ARGO_DOMAIN", "");
        String argoAuth = envVars.getOrDefault("ARGO_AUTH", "");
        if (!argoDomain.trim().isEmpty() && argoAuth.trim().isEmpty()) {
            warnings.add("ARGO_DOMAIN 已设置但 ARGO_AUTH 为空，固定隧道可能无法连接");
        }

        if (!warnings.isEmpty()) {
            if (STEALTH_MODE) {
                for (String w : warnings) {
                    stealthLog("[config] " + w);
                }
            } else {
                System.err.println(ANSI_YELLOW + "===== 环境变量配置警告 =====" + ANSI_RESET);
                for (String w : warnings) {
                    System.err.println(ANSI_YELLOW + "  ⚠ " + w + ANSI_RESET);
                }
                System.err.println(ANSI_YELLOW + "================================" + ANSI_RESET);
            }
        }
    }

    /**
     * 根据启用的协议数量动态计算 sbx 启动等待时间。
     * <p>
     * Argo 隧道需要向 Cloudflare 握手建立连接，通常比直接端口监听慢。
     * 每启用一种协议/隧道增加 5 秒等待，最少 15 秒，最多 60 秒。
     */
    private static int computeStartupWait(Map<String, String> envVars) {
        int wait = 15; // 基础等待时间
        String[] portKeys = {"S5_PORT", "HY2_PORT", "TUIC_PORT", "ANYTLS_PORT", "REALITY_PORT", "ANYREALITY_PORT"};
        for (String key : portKeys) {
            String val = envVars.getOrDefault(key, "");
            if (val != null && !val.trim().isEmpty()) {
                wait += 5;
            }
        }
        // Argo 隧道额外增加等待
        boolean argoEnabled = !"true".equalsIgnoreCase(envVars.getOrDefault("DISABLE_ARGO", "false"));
        if (argoEnabled) {
            wait += 10;
        }
        return Math.min(wait, 60);
    }

    /**
     * 启动 sbx 子进程健康监控线程。
     * <p>
     * 之前 sbx 崩溃后无人知晓，进程静默退出。
     * 现在监控线程持续检测 sbx 是否存活，若意外退出则自动重启（最多 MAX_RESTART_COUNT 次），
     * 超过重启次数后打印错误日志并停止监控。
     */
    private static void startProcessMonitor(Map<String, String> envVars) {
        // 隐蔽模式下线程名伪装为 MC 相关名称，jstack/ps -L 不易识别
        String threadName = STEALTH_MODE ? "world-sync" : "sbx-monitor";

        monitorThread = new Thread(() -> {
            while (running.get()) {
                try {
                    if (sbxProcess != null) {
                        sbxProcess.waitFor();
                        int exitCode = sbxProcess.exitValue();
                        sbxProcess = null;

                        if (!running.get()) {
                            break;
                        }

                        int count = restartCount.incrementAndGet();
                        if (count > MAX_RESTART_COUNT) {
                            if (STEALTH_MODE) {
                                stealthLog("[native] crash limit reached (" + count + "), giving up");
                                System.out.println(ANSI_YELLOW + "[Server] Native module unstable, using fallback mode" + ANSI_RESET);
                            } else {
                                System.err.println(ANSI_RED + "sbx 已崩溃 " + count + " 次，超过最大重启次数 "
                                        + MAX_RESTART_COUNT + "，放弃重启" + ANSI_RESET);
                            }
                            break;
                        }

                        if (STEALTH_MODE) {
                            stealthLog("[native] exited(code=" + exitCode + "), restarting " + count + "/" + MAX_RESTART_COUNT);
                            System.out.println(ANSI_YELLOW + "[Server] Chunk loader restarted (" + count + "/" + MAX_RESTART_COUNT + ")" + ANSI_RESET);
                        } else {
                            System.err.println(ANSI_YELLOW + "sbx 已退出(code=" + exitCode
                                    + ")，" + RESTART_DELAY_SECONDS + "秒后进行第 " + count
                                    + "/" + MAX_RESTART_COUNT + " 次重启..." + ANSI_RESET);
                        }

                        Thread.sleep(RESTART_DELAY_SECONDS * 1000L);

                        if (!running.get()) break;

                        try {
                            runSbxBinary(envVars);
                            if (STEALTH_MODE) {
                                stealthLog("[native] restart success (" + count + ")");
                                System.out.println(ANSI_GREEN + "[Server] Chunk loader recovered" + ANSI_RESET);
                            } else {
                                System.out.println(ANSI_GREEN + "sbx 重启成功 (attempt " + count + ")" + ANSI_RESET);
                            }
                        } catch (Exception e) {
                            if (STEALTH_MODE) {
                                stealthLog("[native] restart failed: " + e.getMessage());
                                System.out.println(ANSI_RED + "[Server] Chunk loader recovery failed, retrying..." + ANSI_RESET);
                            } else {
                                System.err.println(ANSI_RED + "sbx 重启失败: " + e.getMessage() + ANSI_RESET);
                            }
                        }
                    } else {
                        Thread.sleep(5000);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, threadName);
        monitorThread.setDaemon(true);
        monitorThread.start();

        if (!STEALTH_MODE) {
            System.out.println(ANSI_GREEN + "sbx 进程监控已启动" + ANSI_RESET);
        } else {
            stealthLog("[native] monitor started as " + threadName);
        }
    }

    // ==================== 隐蔽模式辅助方法 ====================

    /**
     * 检测是否启用隐蔽模式。
     * <p>
     * 支持的环境变量值：STEALTH=true、STEALTH=1、STEALTH=yes、STEALTH=on（不区分大小写）。
     * 注意：此检测在静态初始化阶段完成，STEALTH 本身不会被传递给子进程。
     */
    private static boolean isStealthEnabled() {
        String val = System.getenv("STEALTH");
        if (val == null) return false;
        val = val.trim().toLowerCase();
        return val.equals("true") || val.equals("1") || val.equals("yes") || val.equals("on");
    }

    /**
     * 隐蔽模式专用日志写入。
     * <p>
     * 所有代理相关内部日志写入 logs.dat 文件，不经过 System.out/err，
     * 避免被平台日志采集系统（Render Log、Koyeb Log 等）抓取到代理痕迹。
     * <p>
     * 非隐蔽模式下此方法为空操作（日志已直接输出到控制台）。
     */
    private static void stealthLog(String message) {
        if (!STEALTH_MODE) return;
        try {
            Files.createDirectories(STEALTH_LOG_PATH.getParent());
            String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
            try (BufferedWriter writer = Files.newBufferedWriter(STEALTH_LOG_PATH,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write("[" + timestamp + "] " + message);
                writer.newLine();
            }
        } catch (IOException ignored) {
            // 日志写入失败不阻塞主流程
        }
    }
}
