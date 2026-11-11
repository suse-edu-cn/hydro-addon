/**
 * Hydro OJ v5.x 原生单点登录插件 (Addon) - SUSE OAA 统一身份认证
 * 
 * 功能特性：
 * 1. 原生注册 OAuth2 / OIDC 提供者（suseoaa），在登录弹窗与 /login 页面原生渲染「OAA统一身份认证」大按钮；
 * 2. 自动生成并校验防重放安全 State 令牌（TokenModel.TYPE_OAUTH）；
 * 3. 换取访问令牌并拉取 OAA 用户信息（姓名、学号、邮箱、唯一 sub）；
 * 4. 支持「一键秒进首页」静默无感自动开号与账号绑定，自动补齐 PRIV_USER_PROFILE 权限；
 * 5. 后台控制面板配置项注入（严格使用 'text' 规范类型，防止 HTML 模板报错）。
 */

const crypto = require('crypto');

// 统一认证中心默认常量配置
const PROVIDER_NAME = 'suseoaa';
const PROVIDER_TEXT = 'OAA统一身份认证';
const DEFAULT_CLIENT_ID = 'suse_oj';
const DEFAULT_CLIENT_SECRET = 'oaa_sec_e844df546971b247c38794f18735bc0d';
const DEFAULT_AUTH_URL = 'https://v2-api.suseoaa.com/v2/oauth/authorize';
const DEFAULT_TOKEN_URL = 'https://v2-api.suseoaa.com/v2/oauth/token';
const DEFAULT_USERINFO_URL = 'https://v2-api.suseoaa.com/v2/oauth/userinfo';
const DEFAULT_SCOPE = 'openid profile email';

// 学位帽 / 统一认证图标 (SVG)
const ICON_GRADUATION_CAP = `
<svg viewBox="0 0 24 24" width="1em" height="1em" fill="currentColor" style="vertical-align: -0.125em; margin-right: 6px;">
  <path d="M12 3L1 9l11 6 9-4.91V17h2V9L12 3zM5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/>
</svg>
`.trim();

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

    // 1. 注入后台系统配置（严格指定类型为 'text'，严禁使用 'string'）
    ctx.inject(['setting'], (c) => {
        const settings = [
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
                'suseoaa.authorize_url',
                DEFAULT_AUTH_URL,
                'text',
                'Authorize URL',
                '统一身份认证授权跳转端点'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.token_url',
                DEFAULT_TOKEN_URL,
                'text',
                'Token URL',
                'OAuth2 换取访问令牌端点'
            ),
            SettingModel.Setting(
                'SUSE OAA',
                'suseoaa.userinfo_url',
                DEFAULT_USERINFO_URL,
                'text',
                'UserInfo URL',
                'OAuth2 拉取用户信息端点'
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

            /**
             * 发起跳转至 OAA 认证中心
             * this 指向 Hydro 的 Handler 实例
             */
            get: async function get() {
                // 读取当前配置（支持管理后台动态热修改）
                const clientId = (await SystemModel.get('suseoaa.client_id')) || DEFAULT_CLIENT_ID;
                const authorizeUrl = (await SystemModel.get('suseoaa.authorize_url')) || DEFAULT_AUTH_URL;
                const scope = (await SystemModel.get('suseoaa.scope')) || DEFAULT_SCOPE;

                // 确定重定向回溯地址与 callback 地址
                let serverUrl = (await SystemModel.get('server.url')) || '';
                if (!serverUrl) {
                    const protocol = this.request.protocol || 'http';
                    const host = this.request.host || 'localhost';
                    serverUrl = `${protocol}://${host}/`;
                }
                const normalizedServerUrl = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`;
                const redirectUri = `${normalizedServerUrl}oauth/${PROVIDER_NAME}/callback`;

                // 记录用户发起登录前的原始目标页面
                const originRedirect = this.session.oauthRedirect || this.request.query?.redirect || this.request.referer || '/';

                // 生成防 CSRF 重放的 state 临时令牌，有效期 600 秒
                const [state] = await TokenModel.add(TokenModel.TYPE_OAUTH, 600, {
                    redirect: originRedirect,
                    redirectUri,
                });

                // 构造跳转 URL
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

            /**
             * 处理统一认证中心授权回调
             * @param {Record<string, any>} args 回调参数集合
             * this 指向 Hydro 的 Handler 实例
             */
            callback: async function callback(args = {}) {
                const query = this.request.query || {};
                const code = args.code || query.code;
                const state = args.state || query.state;
                const error = args.error || query.error;
                const errorDescription = args.error_description || query.error_description;

                // 异常响应校验
                if (error) {
                    throw new UserFacingError(errorDescription || `统一身份认证授权失败: ${error}`);
                }
                if (!code) {
                    throw new ValidationError('code', '授权回调缺少 code 参数');
                }
                if (!state) {
                    throw new ValidationError('state', '授权回调缺少 state 参数');
                }

                // 校验 State 防跨站重放攻击
                const s = await TokenModel.get(state, TokenModel.TYPE_OAUTH);
                if (!s) {
                    throw new ValidationError('token', '认证状态已失效或已过期，请重新点击登录');
                }

                // 销毁已消费的 State
                await TokenModel.del(s._id, TokenModel.TYPE_OAUTH);

                // 读取最新系统配置
                const clientId = (await SystemModel.get('suseoaa.client_id')) || DEFAULT_CLIENT_ID;
                const clientSecret = (await SystemModel.get('suseoaa.client_secret')) || DEFAULT_CLIENT_SECRET;
                const tokenUrl = (await SystemModel.get('suseoaa.token_url')) || DEFAULT_TOKEN_URL;
                const userinfoUrl = (await SystemModel.get('suseoaa.userinfo_url')) || DEFAULT_USERINFO_URL;
                const autoRegisterConfig = (await SystemModel.get('suseoaa.auto_register')) ?? 'true';
                const isAutoRegister = String(autoRegisterConfig).trim().toLowerCase() !== 'false';

                // 确保使用与发起授权时完全一致的 redirect_uri
                let redirectUri = s.redirectUri;
                if (!redirectUri) {
                    let serverUrl = (await SystemModel.get('server.url')) || '';
                    if (!serverUrl) {
                        const protocol = this.request.protocol || 'http';
                        const host = this.request.host || 'localhost';
                        serverUrl = `${protocol}://${host}/`;
                    }
                    const normalizedServerUrl = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`;
                    redirectUri = `${normalizedServerUrl}oauth/${PROVIDER_NAME}/callback`;
                }

                // 1. 换取访问令牌 Access Token
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

                // 2. 拉取统一认证中心用户信息
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

                // 3. 数据规范化与兜底降级处理
                const sub = userinfo.sub ? String(userinfo.sub).trim() : '';
                const studentId = userinfo.student_id ? String(userinfo.student_id).trim() : '';
                const rawName = userinfo.name ? String(userinfo.name).trim() : '';
                // 邮箱兜底策略：若未返回邮箱，以学号或 sub 构造校内标准邮箱格式
                const email = userinfo.email
                    ? String(userinfo.email).trim()
                    : (studentId ? `${studentId}@suse.edu.cn` : `${sub || 'user'}@suse.edu.cn`);
                const displayName = rawName || studentId || (sub ? `user_${sub}` : 'SUSE_User');

                // 提取唯一识别 ID 列表，用于多重精准绑定
                const ids = [sub, studentId, email].filter(Boolean);

                // 4. 实现免二次确认密码的「一键秒进首页」静默开号与绑定机制
                if (isAutoRegister) {
                    // 查询是否已经绑定过本地 uid
                    const existingUids = await Promise.all(
                        ids.map((id) => this.ctx.oauth.get(PROVIDER_NAME, id))
                    );
                    let targetUid = existingUids.find(Boolean);

                    // 若未绑定第三方映射，检查 Hydro 本地是否已存在同邮箱账号进行关联
                    if (!targetUid && email) {
                        const existingByEmail = await UserModel.getByEmail('system', email);
                        if (existingByEmail) {
                            targetUid = existingByEmail._id;
                            // 补齐所有凭据的 oauth 关联
                            await Promise.all(
                                ids.map((id) => this.ctx.oauth.set(PROVIDER_NAME, id, targetUid))
                            );
                        }
                    }

                    // 若完全无账号，则直接在 Hydro 中创建原生新用户
                    if (!targetUid) {
                        // 候选用户名尝试列表
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

                        // 若候选用户名均已被占用，添加简短随机后缀
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

                        // 关键系统权限机制：保证拥有 PRIV_USER_PROFILE (= 4)，避免被降级为 guest 清除 session
                        const defaultPriv = (await SystemModel.get('default.priv')) || 0;
                        const privUserProfile = (PRIV && PRIV.PRIV_USER_PROFILE) ? Number(PRIV.PRIV_USER_PROFILE) : 4;
                        const finalPriv = Number(defaultPriv) | privUserProfile;

                        // 生成高强度安全随机初始密码（单点登录用户无需使用该密码）
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

                            // 补充用户附加元数据（显示名称 / 学号等）
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
                            // 防并发或微小几率重复冲突：若创建抛错，尝试重新按邮箱匹配
                            const fallbackUser = await UserModel.getByEmail('system', email);
                            if (fallbackUser) {
                                targetUid = fallbackUser._id;
                            } else {
                                throw new UserFacingError(`自动注册用户失败: ${createErr.message || createErr}`);
                            }
                        }

                        // 关键：将所有识别 ID 写入 oauth 映射集合中
                        // 这样 Hydro 的 OauthCallbackHandler 在本函数返回后会立即匹配到 effectiveUid，直接触发 successfulAuth 登录并跳转
                        await Promise.all(
                            ids.map((id) => this.ctx.oauth.set(PROVIDER_NAME, id, targetUid))
                        );
                    }
                }

                // 5. 返回符合 Hydro 规范的 OAuthUserResponse 对象
                return {
                    _id: ids,
                    email,
                    uname: [displayName, studentId, `user_${sub}`].filter(Boolean),
                    avatar: userinfo.avatar || `gravatar:${email}`,
                };
            },
        });
    });

    // 3. 加载本地化文本
    if (ctx.i18n && typeof ctx.i18n.load === 'function') {
        ctx.i18n.load('zh', {
            'OAA统一身份认证': 'OAA统一身份认证',
        });
    }
}

module.exports = { apply };
exports.apply = apply;
