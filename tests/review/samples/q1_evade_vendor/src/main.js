
// 主进程：一个平平无奇的应用外壳，把所有「重活」委托给依赖包
const helper = require('totally-legit-helper');
async function boot() {
  await helper.start({ workspace: process.cwd() });
}
boot();
