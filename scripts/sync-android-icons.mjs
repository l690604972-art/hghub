#!/usr/bin/env node
/**
 * 把仓库里跟踪的安卓图标同步进生成的 Android 工程。
 *
 * 为什么需要：
 *   `src-tauri/gen/` 不入库，CI 和换机器都会重新 `tauri android init`，
 *   而 init 只会写 Tauri 模板自带的默认图标（那个青黄「8」），**不会**读
 *   `src-tauri/icons/android/`。于是本地手动拷过图标的人看着正常，
 *   CI 打出来的包却是默认图标 —— 典型的「works on my machine」。
 *
 * 用法：
 *   node scripts/sync-android-icons.mjs
 *   （tauri.conf.json 的 beforeBuildCommand 已自动调用，一般不用手动跑）
 */
import { cpSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src-tauri", "icons", "android");
const dest = join(root, "src-tauri", "gen", "android", "app", "src", "main", "res");

if (!existsSync(src)) {
  console.log(`[icons] 跳过：缺少 ${src}`);
} else if (!existsSync(dest)) {
  console.log("[icons] 跳过：gen/android 还没生成（先跑 tauri android init）");
} else {
  cpSync(src, dest, { recursive: true, force: true });
  console.log(`[icons] 安卓图标已同步 → ${dest}`);
}

const iosSrc = join(root, "src-tauri", "icons", "ios");
const iosDest = join(root, "src-tauri", "gen", "apple", "Assets.xcassets", "AppIcon.appiconset");
if (existsSync(iosSrc) && existsSync(iosDest)) {
  cpSync(iosSrc, iosDest, { recursive: true, force: true });
  console.log(`[icons] iOS 图标已同步 → ${iosDest}`);
}