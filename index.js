/**
 * Hydro OJ v5.x 原生单点登录插件 (Addon) - SUSE OAA 统一身份认证
 * 
 * 功能特性：
 * 1. 支持标准 OIDC Discovery 协议：只需填写主域名（Issuer），插件全自动通过 /.well-known/openid-configuration 发现授权、令牌、用户信息端点；
 * 2. 动态自适应补齐绝对公网回调地址（强制纠正 Hydro 默认 server.url 为 '/' 导致的相对路径问题）；
 * 3. 原生注册 OAuth2 / OIDC 提供者（suseoaa），在登录弹窗与 /login 页面原生渲染「OAA统一身份认证」大按钮；
 * 4. 自动生成并校验防重放安全 State 令牌（TokenModel.TYPE_OAUTH）；
 * 5. 换取访问令牌并拉取 OAA 用户信息（姓名、学号、邮箱、唯一 sub）；
 * 6. 支持「一键秒进首页」静默无感自动开号与账号绑定，自动补齐 PRIV_USER_PROFILE 权限；
 * 7. 后台控制面板配置项注入（严格使用 'text' 规范类型，防止 HTML 模板报错）。
 */

const crypto = require('crypto');

// 统一认证中心默认常量配置
const PROVIDER_NAME = 'suseoaa';
const PROVIDER_TEXT = 'OAA统一身份认证';
const DEFAULT_ISSUER = 'https://v2-api.suseoaa.com';
const DEFAULT_CLIENT_ID = 'suse_oj';
const DEFAULT_CLIENT_SECRET = 'oaa_sec_e844df546971b247c38794f18735bc0d';
const DEFAULT_SCOPE = 'openid profile email';

// 学位帽 / 统一认证图标 (SVG)
const ICON_GRADUATION_CAP = `
<svg viewBox="0 0 24 24" width="1em" height="1em" fill="currentColor" style="vertical-align: -0.125em; margin-right: 6px;">
  <path d="M12 3L1 9l11 6 9-4.91V17h2V9L12 3zM5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/>
</svg>
`.trim();

// OIDC 元数据内存缓存，避免每次用户点击都发起额外的发现请求
let oidcConfigCache = null;
let oidcConfigCacheTime = 0;
let cachedIssuer = '';

/**
 * 规范化主域名 / Issuer URL
 * @param {string} raw
 * @returns {string}
 */
function normalizeIssuer(raw) {
    let str = String(raw || DEFAULT_ISSUER).trim();
    if (!str.startsWith('http://') && !str.startsWith('https://')) {
        str = `https://${str}`;
    }
    return str.replace(/\/+$/, '');
}

/**
 * 提取并构造合法的绝对路径 Server URL（保证包含协议和主机名，杜绝 OAuth 重定向 URI 为相对路径）
 * @param {any} handler Hydro Handler 实例
 * @param {string} configuredUrl 从 SystemModel.get('server.url') 取到的配置
 * @returns {string} 例如 "https://oj.suse.edu.cn/"
 */
function getAbsoluteServerUrl(handler, configuredUrl) {
    let url = String(configuredUrl || '').trim();
    // Hydro 默认初始值为 '/'，或者管理员未填入 http 开头的完整域名
    if (!url || url === '/' || !url.startsWith('http')) {
        const headers = handler.request?.header || {};
        const proto = headers['x-forwarded-proto']
            || handler.request?.protocol
            || 'http';
        const host = headers['x-forwarded-host']
            || headers.host
            || handler.request?.host
            || 'localhost';
        url = `${proto}://${host}/`;
    }
    return url.endsWith('/') ? url : `${url}/`;
}

/**
 * 通过 OIDC 发现端点获取或解析标准端点地址
 * @param {any} superagent
 * @param {string} rawIssuer
 * @returns {Promise<{ authorization_endpoint: string, token_endpoint: string, userinfo_endpoint: string }>}
 */
async function getOidcEndpoints(superagent, rawIssuer) {
    const issuer = normalizeIssuer(rawIssuer);
    const now = Date.now();

    // 缓存有效期 1 小时，且当配置的主域名发生变更时自动失效重新发现
    if (oidcConfigCache && cachedIssuer === issuer && (now - oidcConfigCacheTime < 3600000)) {
        return oidcConfigCache;
    }

    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
    try {
        const res = await superagent
            .get(discoveryUrl)
            .timeout({ response: 5000, deadline: 8000 })
            .set('Accept', 'application/json');

        if (res.body && res.body.authorization_endpoint && res.body.token_endpoint) {
            oidcConfigCache = {
                authorization_endpoint: res.body.authorization_endpoint,
                token_endpoint: res.body.token_endpoint,
                userinfo_endpoint: res.body.userinfo_endpoint || `${issuer}/v2/oauth/userinfo`,
            };
            oidcConfigCacheTime = now;
            cachedIssuer = issuer;
            return oidcConfigCache;
        }
    } catch (err) {
        // 当发现接口临时网络异常或无法访问时，优雅降级为 OIDC 标准默认路径
    }

    // 降级兜底方案
    return {
        authorization_endpoint: `${issuer}/v2/oauth/authorize`,
        token_endpoint: `${issuer}/v2/oauth/token`,
        userinfo_endpoint: `${issuer}/v2/oauth/userinfo`,
    };
}

/**
 * 插件入口 apply 函数 (Cordis 微内核)
 * @param {import('hydrooj').Context} ctx
 */
function apply(ctx) {
    // 动态引用 HydroOJ 核心模型与工具
    const {
        SystemModel,
        SettingModel,
        TokenModel,
        UserModel,
        PRIV,
        UserFacingError,
        ValidationError,
        superagent,
    } = require('hydrooj');

    /**
     * 统一解析当前生效的端点（支持自动发现与手动单项覆盖）
     */
    async function resolveEndpoints() {
        const issuer = (await SystemModel.get('suseoaa.issuer')) || DEFAULT_ISSUER;
        const oidc = await getOidcEndpoints(superagent, issuer);

        const customAuth = (await SystemModel.get('suseoaa.authorize_url')) || '';
        const customToken = (await SystemModel.get('suseoaa.token_url')) || '';
        const customUserinfo = (await SystemModel.get('suseoaa.userinfo_url')) || '';

        return {
            authorizeUrl: customAuth.trim() || oidc.authorization_endpoint,
            tokenUrl: customToken.trim() || oidc.token_endpoint,
            userinfoUrl: customUserinfo.trim() || oidc.userinfo_endpoint,
        };
    }

    // 1. 注入后台系统配置（严格指定类型为 'text'，严禁使用 'string'）
    ctx.inject(['setting'], (c) => {
        const settings = [
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.issuer',
                DEFAULT_ISSUER,
                'text',
                '统一认证主域名 (Issuer)',
                '认证中心根地址（填入主域名如 https://v2-api.suseoaa.com 即可，自动通过 OIDC Discovery 发现端点）'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.client_id',
                DEFAULT_CLIENT_ID,
                'text',
                'Client ID',
                'SUSE OAA OAuth2 客户端标识 (Client ID)'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.client_secret',
                DEFAULT_CLIENT_SECRET,
                'text',
                'Client Secret',
                'SUSE OAA OAuth2 客户端密钥 (Client Secret)',
                SettingModel.FLAG_SECRET || 4
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.scope',
                DEFAULT_SCOPE,
                'text',
                'Scope',
                'OAuth2 申请权限范围 (空格分隔)'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.auto_register',
                'true',
                'text',
                '静默自动开号 (true/false)',
                '首次认证且无绑定用户时，是否自动创建账号并一键进入系统（填 true 或 false）'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.authorize_url',
                '',
                'text',
                '【高级选填】自定义 Authorize URL',
                '默认留空即可自动发现；若填写则覆盖自动发现的授权端点'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.token_url',
                '',
                'text',
                '【高级选填】自定义 Token URL',
                '默认留空即可自动发现；若填写则覆盖自动发现的令牌端点'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.userinfo_url',
                '',
                'text',
                '【高级选填】自定义 UserInfo URL',
                '默认留空即可自动发现；若填写则覆盖自动发现的用户信息端点'
            ),
        ];

        if (c.setting && typeof c.setting.SystemSetting === 'function') {
            c.setting.SystemSetting(...settings);
        } else if (typeof SettingModel.SystemSetting === 'function') {
            SettingModel.SystemSetting(...settings);
        }
    });

    // 2. 注入并注册 OAuth Provider
    ctx.inject(['oauth', 'setting'], (c) => {
        c.oauth.provide(PROVIDER_NAME, {
            text: PROVIDER_TEXT,
            name: 'SUSE OAA',
            icon: ICON_GRADUATION_CAP,
            canRegister: true,

            get: async function get() {
                // 1. 读取客户端配置与动态发现的端点
                const clientId = (await SystemModel.get('suseoaa.client_id')) || DEFAULT_CLIENT_ID;
                const scope = (await SystemModel.get('suseoaa.scope')) || DEFAULT_SCOPE;
                const { authorizeUrl } = await resolveEndpoints();

                // 2. 严格生成合法的绝对公网回跳地址 redirect_uri
                const configuredServerUrl = await SystemModel.get('server.url');
                const serverUrl = getAbsoluteServerUrl(this, configuredServerUrl);
                const redirectUri = `${serverUrl}oauth/${PROVIDER_NAME}/callback`;

                // 3. 记录用户发起登录前的原始目标页面
                const originRedirect = this.session.oauthRedirect || this.request.query?.redirect || this.request.referer || '/';

                // 4. 生成防 CSRF 重放的 state 临时令牌，有效期 600 秒
                const [state] = await TokenModel.add(TokenModel.TYPE_OAUTH, 600, {
                    redirect: originRedirect,
                    redirectUri,
                });

                // 5. 构造跳转 URL
                const queryParams = new URLSearchParams({
                    response_type: 'code',
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    scope,
                    state,
                });

                const target = `${authorizeUrl}${authorizeUrl.includes('?') ? '&' : '?'}${queryParams.toString()}`;
                this.response.redirect = target;
            },

            callback: async function callback(args = {}) {
                const query = this.request.query || {};
                const code = args.code || query.code;
                const state = args.state || query.state;
                const error = args.error || query.error;
                const errorDescription = args.error_description || query.error_description;

                if (error) {
                    throw new UserFacingError(errorDescription || `统一身份认证授权失败: ${error}`);
                }
                if (!code) {
                    throw new ValidationError('code', '授权回调缺少 code 参数');
                }
                if (!state) {
                    throw new ValidationError('state', '授权回调缺少 state 参数');
                }

                const s = await TokenModel.get(state, TokenModel.TYPE_OAUTH);
                if (!s) {
                    throw new ValidationError('token', '认证状态已失效或已过期，请重新点击登录');
                }

                await TokenModel.del(s._id, TokenModel.TYPE_OAUTH);

                const clientId = (await SystemModel.get('suseoaa.client_id')) || DEFAULT_CLIENT_ID;
                const clientSecret = (await SystemModel.get('suseoaa.client_secret')) || DEFAULT_CLIENT_SECRET;
                const autoRegisterConfig = (await SystemModel.get('suseoaa.auto_register')) ?? 'true';
                const isAutoRegister = String(autoRegisterConfig).trim().toLowerCase() !== 'false';
                const { tokenUrl, userinfoUrl } = await resolveEndpoints();

                // 严格保证使用与发起授权时完全一致的绝对 redirect_uri
                let redirectUri = s.redirectUri;
                if (!redirectUri || !redirectUri.startsWith('http')) {
                    const configuredServerUrl = await SystemModel.get('server.url');
                    const serverUrl = getAbsoluteServerUrl(this, configuredServerUrl);
                    redirectUri = `${serverUrl}oauth/${PROVIDER_NAME}/callback`;
                }

                let accessToken = '';
                try {
                    const tokenRes = await superagent
                        .post(tokenUrl)
                        .type('form')
                        .send({
                            grant_type: 'authorization_code',
                            client_id: clientId,
                            client_secret: clientSecret,
                            code,
                            redirect_uri: redirectUri,
                        })
                        .timeout({ response: 10000, deadline: 15000 })
                        .set('Accept', 'application/json');

                    const tokenBody = tokenRes.body || {};
                    if (tokenBody.error) {
                        throw new UserFacingError(tokenBody.error_description || tokenBody.error);
                    }
                    accessToken = tokenBody.access_token;
                    if (!accessToken) {
                        throw new Error('响应未包含有效 access_token 字段');
                    }
                } catch (err) {
                    if (err instanceof UserFacingError) throw err;
                    throw new UserFacingError(`换取访问令牌失败: ${err.message || err}`);
                }

                let userinfo = null;
                try {
                    const userinfoRes = await superagent
                        .get(userinfoUrl)
                        .set('Authorization', `Bearer ${accessToken}`)
                        .set('Accept', 'application/json')
                        .timeout({ response: 10000, deadline: 15000 });

                    userinfo = userinfoRes.body;
                    if (!userinfo || (!userinfo.sub && !userinfo.student_id && !userinfo.email)) {
                        throw new Error('未接收到有效的用户信息对象');
                    }
                } catch (err) {
                    if (err instanceof UserFacingError) throw err;
                    throw new UserFacingError(`获取用户身份信息失败: ${err.message || err}`);
                }

                const sub = userinfo.sub ? String(userinfo.sub).trim() : '';
                const studentId = userinfo.student_id ? String(userinfo.student_id).trim() : '';
                const rawName = userinfo.name ? String(userinfo.name).trim() : '';
                const email = userinfo.email
                    ? String(userinfo.email).trim()
                    : (studentId ? `${studentId}@suse.edu.cn` : `${sub || 'user'}@suse.edu.cn`);
                const displayName = rawName || studentId || (sub ? `user_${sub}` : 'SUSE_User');

                const ids = [sub, studentId, email].filter(Boolean);

                if (isAutoRegister) {
                    const existingUids = await Promise.all(
                        ids.map((id) => this.ctx.oauth.get(PROVIDER_NAME, id))
                    );
                    let targetUid = existingUids.find(Boolean);

                    if (!targetUid && email) {
                        const existingByEmail = await UserModel.getByEmail('system', email);
                        if (existingByEmail) {
                            targetUid = existingByEmail._id;
                            await Promise.all(
                                ids.map((id) => this.ctx.oauth.set(PROVIDER_NAME, id, targetUid))
                            );
                        }
                    }

                    if (!targetUid) {
                        const candidateUnames = [
                            displayName,
                            studentId,
                            `user_${sub}`,
                            `suse_${studentId || sub}`,
                        ].filter(Boolean);

                        let finalUname = '';
                        for (const cand of candidateUnames) {
                            const trimmed = cand.trim();
                            if (!trimmed) continue;
                            const existed = await UserModel.getByUname('system', trimmed);
                            if (!existed) {
                                finalUname = trimmed;
                                break;
                            }
                        }

                        if (!finalUname) {
                            const baseUname = (displayName || studentId || 'user').trim();
                            for (let i = 0; i < 5; i++) {
                                const testUname = `${baseUname}_${crypto.randomBytes(2).toString('hex')}`;
                                const existed = await UserModel.getByUname('system', testUname);
                                if (!existed) {
                                    finalUname = testUname;
                                    break;
                                }
                            }
                            if (!finalUname) {
                                finalUname = `user_${sub}_${Date.now().toString(36)}`;
                            }
                        }

                        const defaultPriv = (await SystemModel.get('default.priv')) || 0;
                        const privUserProfile = (PRIV && PRIV.PRIV_USER_PROFILE) ? Number(PRIV.PRIV_USER_PROFILE) : 4;
                        const finalPriv = Number(defaultPriv) | privUserProfile;

                        const randomPassword = crypto.randomBytes(18).toString('base64');
                        const clientIp = this.request.ip || '127.0.0.1';

                        try {
                            targetUid = await UserModel.create(
                                email,
                                finalUname,
                                randomPassword,
                                undefined,
                                clientIp,
                                finalPriv
                            );

                            const extraMeta = {};
                            if (displayName && displayName !== finalUname) {
                                extraMeta.displayName = displayName;
                            }
                            if (studentId) {
                                extraMeta.studentId = studentId;
                            }
                            if (Object.keys(extraMeta).length > 0) {
                                await UserModel.setById(targetUid, extraMeta);
                            }
                        } catch (createErr) {
                            const fallbackUser = await UserModel.getByEmail('system', email);
                            if (fallbackUser) {
                                targetUid = fallbackUser._id;
                            } else {
                                throw new UserFacingError(`自动注册用户失败: ${createErr.message || createErr}`);
                            }
                        }

                        await Promise.all(
                            ids.map((id) => this.ctx.oauth.set(PROVIDER_NAME, id, targetUid))
                        );
                    }
                }

                return {
                    _id: ids,
                    email,
                    uname: [displayName, studentId, `user_${sub}`].filter(Boolean),
                    avatar: userinfo.avatar || `gravatar:${email}`,
                };
            },
        });
    });

    if (ctx.i18n && typeof ctx.i18n.load === 'function') {
        ctx.i18n.load('zh', {
            'OAA统一身份认证': 'OAA统一身份认证',
        });
    }
}

module.exports = { apply };
exports.apply = apply;
