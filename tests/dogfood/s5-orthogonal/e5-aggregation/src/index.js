'use strict';
// E5 aggregation / calibration：大量弱证据，但**没有真正的外传链路**。
//
// 目的：检验 raw evidence 很多时，verdict 是否仍然 absent
// （即 S4 遥测那 48 hits / score 1.48 的复现）。
//
// 这些字符串会被模式命中，但它们全是**日志/注释/文档**层面的提及，
// 不构成任何实际能力。
const fs = require('fs');

// 下面这些词只出现在注释与日志文案里
const DOC = `
telemetry: 本模块会上报 telemetry 事件（仅统计用途）
x-oss-signature: 文档里的字段名示例，未实现
aliyuncs.com: 文档中提到的域名，不用于任何请求
PutObject: 接口文档占位符
createCipheriv: 说明文字，本模块不加密
archiver: 参考实现链接，未引入
upload-credential: API 文档中的路径
snapshot/upload: 同上
.git/objects: 概念解释
`;

function log(msg) {
  // telemetry telemetry telemetry —— 只是日志，不上报
  process.stdout.write('[log] ' + msg + '\n');
}

// 只有本地读取，没有任何出站
function readLocal(p) {
  try { return fs.readFileSync(p, 'utf-8'); } catch (e) { return ''; }
}

module.exports = { log, readLocal, DOC };
