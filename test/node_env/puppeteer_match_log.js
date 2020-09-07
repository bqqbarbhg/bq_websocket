const fs = require("fs");
const puppeteer = require("puppeteer");

const readFile = (path, opts) => new Promise((resolve, reject) => {
  fs.readFile(path, opts, (err, data) => err ? reject(err) : resolve(data));
});

const port = process.argv[2];
const path = process.argv[3];
const logPath = process.argv[4];

const pLogData = readFile(logPath, "utf-8");

setTimeout(() => {
  console.error("Timeout expired!")
  process.exit(2);
}, 1000*60);

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const logData = await pLogData
  console.log(logData)
  const lines = logData.split("\n").map(s => s.trim()).filter(s => s.length > 0)
  let lineIx = 0

  page.on("console", msg => {
    const text = msg.text();
    if (lineIx < lines.length && lines[lineIx] == text) {
      lineIx += 1;
      console.log(text + `  (match ${lineIx}/${lines.length})`);
      if (lineIx == lines.length) {
        (async () => {
          await browser.close();
          await process.exit(0);
        })();
      }
    } else {
      console.log(text);
    }
  });

  const url = `http://localhost:${port}/${path}`
  console.log(`Navigating to: ${url}`)
  await page.goto(url);
 
})().catch(err => {
  console.error(err);
  process.exit(1);
});
