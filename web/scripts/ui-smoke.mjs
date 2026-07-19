import { chromium } from 'playwright-core'

const baseURL = process.env.PROXYLOOM_UI_URL || 'http://127.0.0.1:18088'
const username = process.env.PROXYLOOM_UI_USERNAME
const password = process.env.PROXYLOOM_UI_PASSWORD
const executablePath = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

if (!username || !password) throw new Error('temporary UI username and password are required')

const browser = await chromium.launch({ executablePath, headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 920 }, locale: 'zh-CN' })
const page = await context.newPage()
const consoleErrors = []
page.on('console', message => {
	if (message.type() === 'error' && !message.text().startsWith('Failed to load resource:')) consoleErrors.push(message.text())
})
page.on('pageerror', error => consoleErrors.push(error.message))
page.on('response', response => {
	if (response.status() < 400) return
	const expectedAnonymousSession = response.status() === 401 && response.url().endsWith('/api/v1/session')
	if (!expectedAnonymousSession) consoleErrors.push(`${response.status()} ${response.url()}`)
})

await page.goto(baseURL, { waitUntil: 'networkidle' })
await page.getByLabel('用户名').fill(username)
await page.getByLabel('密码', { exact: true }).fill(password)
await page.getByRole('button', { name: '登录' }).click()
await page.getByRole('heading', { name: '总览', exact: true }).waitFor()
await page.waitForFunction(() => Number(document.querySelector('.summary-strip strong')?.textContent || '0') > 0)
await page.screenshot({ path: '/tmp/proxyloom-ui-desktop.png', fullPage: true })

await page.getByRole('button', { name: '订阅管理', exact: true }).click()
await page.getByRole('heading', { name: '订阅管理', exact: true }).waitFor()
await page.locator('.toolbar').getByRole('button', { name: '添加订阅', exact: true }).click()
await page.getByRole('dialog').waitFor()
await page.screenshot({ path: '/tmp/proxyloom-ui-source-dialog.png', fullPage: true })
await page.getByTitle('关闭').click()
const editSourceButton = page.getByTitle('编辑订阅').first()
if (await editSourceButton.count()) {
	await editSourceButton.click()
	await page.getByRole('dialog').waitFor()
	await page.screenshot({ path: '/tmp/proxyloom-ui-source-edit.png' })
	await page.getByTitle('关闭').click()
}

await page.getByRole('button', { name: '节点健康', exact: true }).click()
await page.getByRole('heading', { name: '节点健康', exact: true }).waitFor()
const detailButton = page.getByTitle('查看检查记录').first()
if (await detailButton.count()) {
	await detailButton.click()
	await page.getByRole('dialog').waitFor()
	await page.screenshot({ path: '/tmp/proxyloom-ui-node-health.png' })
	await page.getByTitle('关闭').click()
}

await page.getByRole('button', { name: '聚合与规则', exact: true }).click()
await page.getByRole('heading', { name: '聚合与规则', exact: true }).waitFor()
await page.getByRole('button', { name: '节点处理脚本', exact: true }).click()
await page.screenshot({ path: '/tmp/proxyloom-ui-pipelines.png' })

await page.getByRole('button', { name: '设置', exact: true }).click()
await page.getByRole('heading', { name: '设置', exact: true }).waitFor()
await page.screenshot({ path: '/tmp/proxyloom-ui-settings.png' })

await page.getByRole('button', { name: '使用说明', exact: true }).click()
await page.getByRole('heading', { name: '使用说明', exact: true }).waitFor()
await page.screenshot({ path: '/tmp/proxyloom-ui-guide.png', fullPage: true })

await page.setViewportSize({ width: 390, height: 844 })
await page.getByRole('button', { name: '输出订阅', exact: true }).click()
await page.getByRole('heading', { name: '输出订阅', exact: true }).waitFor()
await page.screenshot({ path: '/tmp/proxyloom-ui-mobile.png' })

const bodyOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)
if (bodyOverflow) throw new Error('page has horizontal body overflow at mobile viewport')
if (consoleErrors.length) throw new Error(`browser console errors: ${consoleErrors.join(' | ')}`)

await browser.close()
