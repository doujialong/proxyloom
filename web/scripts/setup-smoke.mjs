import { chromium } from 'playwright-core'

const baseURL = process.env.PROXYLOOM_UI_URL || 'http://127.0.0.1:18089'
const setupToken = process.env.PROXYLOOM_SETUP_TOKEN
const executablePath = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

if (!setupToken) throw new Error('a temporary administrator setup token is required')

const browser = await chromium.launch({ executablePath, headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 920 }, locale: 'zh-CN' })
const page = await context.newPage()
const errors = []
page.on('console', message => {
	if (message.type() === 'error' && !message.text().startsWith('Failed to load resource:')) errors.push(message.text())
})
page.on('pageerror', error => errors.push(error.message))
page.on('response', response => {
	if (response.status() >= 400) errors.push(`${response.status()} ${response.url()}`)
})

await page.goto(baseURL, { waitUntil: 'networkidle' })
await page.getByRole('heading', { name: '创建首个管理员', exact: true }).waitFor()
await page.getByText('令牌 24 小时内有效且只能使用一次。', { exact: false }).waitFor()
await page.getByText('docker compose run --rm --no-deps proxyloom bootstrap-token', { exact: true }).waitFor()
await page.screenshot({ path: '/tmp/proxyloom-setup-desktop.png' })

await page.setViewportSize({ width: 390, height: 844 })
await page.screenshot({ path: '/tmp/proxyloom-setup-mobile.png', fullPage: true })
const mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)
if (mobileOverflow) throw new Error('setup page has horizontal body overflow at mobile viewport')
await page.setViewportSize({ width: 1440, height: 920 })

await page.getByLabel('初始化令牌').fill(setupToken)
await page.getByLabel('管理员用户名').fill('adm')
await page.getByLabel(/^密码/).fill('1')
await page.getByLabel(/^确认密码/).fill('2')
await page.getByRole('button', { name: '创建管理员并登录', exact: true }).click()
await page.getByText('两次输入的密码不一致。', { exact: true }).waitFor()

await page.getByLabel(/^确认密码/).fill('1')
await page.getByRole('button', { name: '创建管理员并登录', exact: true }).click()
await page.getByRole('heading', { name: '总览', exact: true }).waitFor()

await page.getByTitle('退出登录').click()
await page.getByRole('heading', { name: '管理员登录', exact: true }).waitFor()
await page.getByLabel('用户名', { exact: true }).fill('adm')
await page.getByLabel('密码', { exact: true }).fill('1')
await page.getByRole('button', { name: '登录', exact: true }).click()
await page.getByRole('heading', { name: '总览', exact: true }).waitFor()

if (errors.length) throw new Error(`browser errors: ${errors.join(' | ')}`)
await browser.close()
