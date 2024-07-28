"use strict";Object.defineProperty(exports, "__esModule", {value: true}); function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; } function _nullishCoalesce(lhs, rhsFn) { if (lhs != null) { return lhs; } else { return rhsFn(); } } function _optionalChain(ops) { let lastAccessLHS = undefined; let value = ops[0]; let i = 1; while (i < ops.length) { const op = ops[i]; const fn = ops[i + 1]; i += 2; if ((op === 'optionalAccess' || op === 'optionalCall') && value == null) { return undefined; } if (op === 'access' || op === 'optionalAccess') { lastAccessLHS = value; value = fn(value); } else if (op === 'call' || op === 'optionalCall') { value = fn((...args) => value.call(lastAccessLHS, ...args)); lastAccessLHS = undefined; } } return value; } var _class;// src/base.ts
var _crypto = require('crypto'); var _crypto2 = _interopRequireDefault(_crypto);
var _formdata = require('form-data'); var _formdata2 = _interopRequireDefault(_formdata);
var _axios = require('axios'); var _axios2 = _interopRequireDefault(_axios);
var _path = require('path');
var _fs = require('fs');

// src/utils/index.ts

function urlExclueOrigin(url) {
  const _url = new URL(url);
  return url.replace(_url.origin, "");
}
function unixTimeStamp() {
  return Math.floor(Date.now() / 1e3).toString();
}
function randomStr(length = 32) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const maxPos = chars.length;
  let noceStr = "";
  for (let i = 0; i < (length || 32); i++) {
    noceStr += chars.charAt(Math.floor(Math.random() * maxPos));
  }
  return noceStr;
}
function path2FileName(path) {
  return path.replace(/^.*[\\\/]/, "");
}
function fileSha256(buffer) {
  return _crypto2.default.createHash("sha256").update(buffer).digest("hex");
}
function getCertificateSerialNo(buf) {
  const x509 = new (0, _crypto.X509Certificate)(buf);
  return x509.serialNumber;
}
function getCertificatePublicKey(certString) {
  const x509 = new (0, _crypto.X509Certificate)(certString);
  return x509.publicKey;
}
function encrypt(data, key) {
  return _crypto2.default.publicEncrypt(
    {
      key,
      padding: _crypto2.default.constants.RSA_PKCS1_OAEP_PADDING
    },
    Buffer.from(data, "utf8")
  ).toString("base64");
}
function getToken(mchid, serial_no, nonce_str, timestamp, signature) {
  return `mchid="${mchid}",nonce_str="${nonce_str}",signature="${signature}",serial_no="${serial_no}",timestamp="${timestamp}"`;
}
function decryptToString_AES(options) {
  const { associated_data, ciphertext, key, nonce } = options;
  const ciphertextBuffer = Buffer.from(ciphertext, "base64");
  const authTag = ciphertextBuffer.slice(ciphertextBuffer.length - 16);
  const data = ciphertextBuffer.slice(0, ciphertextBuffer.length - 16);
  const decipherIv = _crypto2.default.createDecipheriv("aes-256-gcm", key, nonce);
  decipherIv.setAuthTag(authTag);
  decipherIv.setAAD(Buffer.from(associated_data));
  const decryptBuf = decipherIv.update(data);
  decipherIv.final();
  return decryptBuf.toString("utf8");
}
function getPublicKey(certString) {
  const x509 = new (0, _crypto.X509Certificate)(certString);
  return x509.publicKey;
}
function isUrl(url) {
  const reg = /^((https|http|ftp)?:\/\/)[^\s]+/;
  return reg.test(url);
}
function getSysTmpDir() {
  return process.env.TMPDIR || process.env.TMP || process.env.TEMP || "/tmp";
}
function getPathValue(obj, path) {
  return path.split(".").reduce((prev, curr) => prev[curr], obj);
}
function setPathValue(obj, path, value, options) {
  let setFlag = true;
  return path.split(".").reduce((prev, curr, index, array) => {
    if (index === array.length - 1 && setFlag) {
      prev[curr] = value;
    }
    if (!prev[curr]) {
      if (_optionalChain([options, 'optionalAccess', _2 => _2.onSetFail]))
        options.onSetFail(array.slice(0, index + 1).join("."));
      setFlag = false;
    }
    return prev[curr];
  }, obj);
}
function replaceTagText(str, params, beforeToken = "{", afterToken = "}") {
  const arr = Object.entries(params);
  let result = str;
  arr.forEach(([key, value]) => {
    result = result.replace(`${beforeToken}${key}${afterToken}`, value);
  });
  return result;
}

// src/base.ts
var WechatPayV3Base = (_class = class {
  constructor(options, events = {}) {;_class.prototype.__init.call(this);_class.prototype.__init2.call(this);
    this.events = events;
    this.mchid = options.mchid;
    this.userAgent = _nullishCoalesce(options.userAgent, () => ( "wechatpay-sdk"));
    this.privateKey = options.apiclient_key;
    this.apiCretSerialNo = getCertificateSerialNo(options.apiclient_cret);
    this.apiV3Key = options.apiV3Key;
    if (options.downloadDir) {
      this.downloadDir = options.downloadDir;
    } else {
      const tempDir = getSysTmpDir();
      const downloadDir = _path.join.call(void 0, tempDir, "./wxpay-v3-downloads");
      if (!_fs.existsSync.call(void 0, downloadDir)) {
        _fs.mkdirSync.call(void 0, downloadDir);
      }
      this.downloadDir = downloadDir;
    }
    this.request = _axios2.default.create({
      timeout: 1e3 * 60 * 5,
      timeoutErrorMessage: "\u8BF7\u6C42\u8D85\u65F6",
      headers: {
        Accept: "application/json",
        "User-Agent": this.userAgent,
        "Content-Type": "application/json"
      }
    });
    this.init();
  }
  /** pem私钥 */
  
  /** 加密算法,固定值'WECHATPAY2-SHA256-RSA2048'.国密暂不支持 */
  __init() {this.schema = "WECHATPAY2-SHA256-RSA2048"}
  /** axios请求示例 */
  
  /** 商户号 */
  
  /** header -> userAgent (微信可能会拒绝不带userAgent的请求) */
  
  /** apiV3密钥 */
  
  /** 平台证书列表 */
  __init2() {this.certificates = []}
  /** 更新证书时间+12小时后的结果,注意此时间并非平台证书本身的过期时间,而是需要更新的时间 */
  
  /** 商户Api证书序列号 */
  
  /** 下载文件文件夹 */
  
  /**
   * 初始化
   */
  init() {
    this.request.interceptors.response.use(
      (response) => {
        if (this.events.onResponse) {
          this.events.onResponse(response, this);
        }
        return response;
      },
      (error) => {
        if (error.response) {
          return Promise.reject(_nullishCoalesce(error.response.data, () => ( error)));
        }
        return Promise.reject(error);
      }
    );
    this.request.interceptors.request.use(async (config) => {
      if (this.events.onRequsetBefore) {
        this.events.onRequsetBefore(config, this);
      }
      if (_optionalChain([config, 'access', _3 => _3.headers, 'optionalAccess', _4 => _4.Authorization]) === void 0) {
        if (config.method && config.url) {
          const timestamp = unixTimeStamp();
          const nonce = randomStr();
          const signature = this.buildMessageSign(
            config.method.toUpperCase(),
            urlExclueOrigin(config.url),
            timestamp,
            nonce,
            config.data || ""
          );
          const Authorization = this.getAuthorization(nonce, timestamp, signature);
          config.headers.Authorization = Authorization;
        }
      }
      if (_optionalChain([config, 'access', _5 => _5.url, 'optionalAccess', _6 => _6.includes, 'call', _7 => _7("/v3/certificates")])) {
        return config;
      }
      await this.updateCertificates();
      if (this.events.onRequsetAfter) {
        this.events.onRequsetAfter(config, this);
      }
      return config;
    });
    this.updateCertificates().catch((error) => {
      console.log("init updateCertificates fail", error);
    });
  }
  setEvents(events) {
    this.events = events;
  }
  /**
   * 更新平台证书
   * @description 会判断缓存是否过期,如果过期则更新,否则不更新.
   * @param forceUpdate 强制更新
   */
  async updateCertificates(forceUpdate = false) {
    if (forceUpdate === false) {
      if (this.certExpiresTime && this.certExpiresTime > /* @__PURE__ */ new Date()) {
        return;
      }
    }
    const res = await this.getCertificates();
    this.certificates = res;
    this.certExpiresTime = new Date(Date.now() + 12 * 60 * 60 * 1e3);
  }
  /**
   * 构造签名串并签名
   * @param method 请求方法
   * @param url 请求URL
   * @param timestamp 时间戳
   * @param nonce 随机字符串
   * @param body 请求主体
   */
  buildMessageSign(method, url, timestamp, nonce, body) {
    const tmpBody = typeof body === "object" ? JSON.stringify(body) : body;
    const data = method + "\n" + url + "\n" + timestamp + "\n" + nonce + "\n" + tmpBody + "\n";
    return this.sha256WithRSA(data);
  }
  /**
   * 构造验签名串
   * @param timestamp 参数在响应头中对应
   * @param nonce 参数在响应头中对应
   * @param body 参数在响应头中对应
   * @returns
   */
  buildMessageVerify(timestamp, nonce, body) {
    return [timestamp, nonce, body].join("\n") + "\n";
  }
  /**
   * 构造Authorization
   * @param nonce_str 随机字符串
   * @param timestamp 时间戳
   * @param signature 签名(buildMessage生成)
   */
  getAuthorization(nonce_str, timestamp, signature) {
    return `${this.schema} ${getToken(this.mchid, this.apiCretSerialNo, nonce_str, timestamp, signature)}`;
  }
  /**
   * 私钥签名
   * @param data 待签名数据
   * @returns base64编码的签名
   */
  sha256WithRSA(data) {
    return _crypto2.default.createSign("RSA-SHA256").update(data).sign(this.privateKey, "base64");
  }
  /**
   * 平台证书公钥验签
   * @param serial 证书序列号
   * @param signature 签名
   * @param data 待验签数据
   */
  sha256WithRsaVerify(serial, signature, data) {
    const cert = this.certificates.find((item) => item.serial_no === serial);
    if (!cert) {
      console.error({
        cerificates: this.certificates,
        certExpiresTime: this.certExpiresTime
      });
      throw new Error("\u8BC1\u4E66\u5E8F\u5217\u53F7\u9519\u8BEF");
    }
    return _crypto2.default.createVerify("RSA-SHA256").update(data).verify(cert.publicKey, signature, "base64");
  }
  /**
   * 解密平台响应
   * @param nonce 随机字符串
   * @param associated_data 附加数据
   * @param ciphertext  密文
   * @returns
   */
  aesGcmDecrypt(options) {
    return decryptToString_AES({
      ...options,
      key: this.apiV3Key
    });
  }
  /**
   * 平台证书公钥加密,如果需要同时加密多个字段,请使用publicEncryptObjectPaths
   * @param data 待加密数据
   * @returns
   */
  publicEncrypt(data) {
    return encrypt(data, this.certificates[0].publicKey);
  }
  /**
   * 平台证书公钥加密请求主体中指定的字段
   * @description 对字符串类型的路径进行加密
   * @param data 数据
   * @param paths 路径数组
   * @returns 该函数返回一个新的对象,不会修改原对象
   * @example
   * const data = { name: '张三' , idCard: {
   *    number:string //如果这个字段需要加密
   * }}
   * const newData = publicEncryptObjectPaths(data,['idCard.number'])
   */
  publicEncryptObjectPaths(data, paths) {
    const json = JSON.stringify(data);
    const newData = JSON.parse(json);
    paths.forEach((path) => {
      const value = getPathValue(newData, path);
      if (value && typeof value === "string") {
        setPathValue(newData, path, this.publicEncrypt(value), {
          onSetFail(failPath) {
            console.log(`\u8BBE\u7F6E\u8DEF\u5F84:${failPath}\u5931\u8D25 : ${json}`);
          }
        });
      }
    });
    return newData;
  }
  /**
   * 下载文件
   * @param url
   * @param fileName 提供文件名,包括后缀。如果不提供,则从url中获取文件名
   * @returns
   */
  async downloadFile(url, fileName) {
    let tmpFileName = fileName || "";
    if (!fileName) {
      tmpFileName = url.split("/").pop();
      if (tmpFileName === "") {
        throw new Error("\u6587\u4EF6\u540D\u83B7\u53D6\u5931\u8D25,\u8BF7\u624B\u52A8\u6307\u5B9A\u6587\u4EF6\u540D");
      }
    }
    const response = await this.request.get(url, {
      responseType: "stream"
    });
    const contentType = response.headers["content-type"];
    const suffix = contentType.split("/").pop();
    if (suffix) {
      if (suffix === "jpeg") {
        tmpFileName = `${tmpFileName}.jpg`;
      } else {
        tmpFileName = `${tmpFileName}.${suffix}`;
      }
    }
    const filePath = _path.join.call(void 0, this.downloadDir, tmpFileName);
    const writer = _fs.createWriteStream.call(void 0, filePath);
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
      writer.on("finish", () => {
        writer.close();
        resolve({
          filePath,
          fileName: tmpFileName
        });
      });
      writer.on("error", reject);
    });
  }
  /**
   * 响应验签
   * @description 该函数会验证签名,返回true表示验签成功,返回false表示验签失败
   * @param headers 请求头
   * @param body  请求体
   */
  resVerify(headers, body) {
    const {
      "wechatpay-timestamp": timestamp,
      "wechatpay-nonce": nonce,
      "wechatpay-signature": signature,
      "wechatpay-serial": serial
    } = headers;
    let bodyStr = "";
    if (body) {
      bodyStr = Object.keys(body).length !== 0 ? JSON.stringify(body) : "";
    }
    const signStr = this.buildMessageVerify(timestamp, nonce, bodyStr);
    return this.sha256WithRsaVerify(serial, signature, signStr);
  }
  /**
   * 处理回调 -验证签名,并使用AEAD_AES_256_GCM解密
   * @param headers
   * @param body
   */
  async handleCallback(headers, body) {
    if (!body.resource) {
      throw new Error("\u56DE\u8C03\u6570\u636E\u683C\u5F0F\u9519\u8BEF");
    }
    const isOk = this.resVerify(headers, body);
    if (!isOk) {
      throw new Error("\u56DE\u8C03\u9A8C\u7B7E\u5931\u8D25");
    }
    const resource = this.aesGcmDecrypt(body.resource);
    try {
      return {
        ...body,
        resource: JSON.parse(resource)
      };
    } catch (error) {
      throw new Error("\u56DE\u8C03\u6570\u636EJSON\u89E3\u6790\u5931\u8D25");
    }
  }
  //================ Base Api
  /**
   * 获取证书
   * @description 获取商户当前可用的平台证书列表。
   * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/wechatpay5_1.shtml
   */
  async getCertificates() {
    const apiUrl = "https://api.mch.weixin.qq.com/v3/certificates";
    const res = await this.request.get(apiUrl);
    const certificates = res.data.data;
    const decryptCertificates = certificates.map((item) => {
      const { associated_data, ciphertext, nonce } = item.encrypt_certificate;
      const certificate = this.aesGcmDecrypt({
        nonce,
        associated_data,
        ciphertext
      });
      const publicKey = getPublicKey(certificate);
      return {
        expire_time: item.expire_time,
        effective_time: item.effective_time,
        serial_no: item.serial_no,
        certificate,
        publicKey
      };
    });
    decryptCertificates.sort((a, b) => {
      return new Date(b.expire_time).getTime() - new Date(a.expire_time).getTime();
    });
    return decryptCertificates;
  }
  //上传视频和图片的方法差不多,封装在一起
  async _upload(path, options) {
    const { fileName, type } = options;
    const apiUrl = "https://api.mch.weixin.qq.com/v3/merchant/media/upload";
    const realyFileName = _nullishCoalesce(fileName, () => ( path2FileName(path)));
    const fileSize = _fs.statSync.call(void 0, path).size;
    if (type === "image") {
      if (!realyFileName.match(/(jpg|png|bmp)$/i)) {
        throw "\u56FE\u7247\u7ED3\u5C3E\u5FC5\u987B\u662Fjpg\u3001png\u3001bmp";
      }
      if (fileSize > 2 * 1024 * 1024) {
        throw "\u56FE\u7247\u5927\u5C0F\u4E0D\u80FD\u8D85\u8FC72M";
      }
    } else if (type === "video") {
      if (!realyFileName.match(/(avi|wmv|mpeg|mp4|mov|mkv|flv|f4v|m4v|rmvb)$/i)) {
        throw "\u89C6\u9891\u7ED3\u5C3E\u5FC5\u987B\u662Favi\u3001wmv\u3001mpeg\u3001mp4\u3001mov\u3001mkv\u3001flv\u3001f4v\u3001m4v\u3001rmvb";
      }
      if (fileSize > 5 * 1024 * 1024) {
        throw "\u89C6\u9891\u5927\u5C0F\u4E0D\u80FD\u8D85\u8FC75M";
      }
    }
    let file;
    try {
      file = _fs.readFileSync.call(void 0, path);
    } catch (error) {
      throw "\u627E\u4E0D\u5230\u6587\u4EF6: " + path;
    }
    const body = {
      filename: realyFileName,
      sha256: fileSha256(file)
    };
    const json = JSON.stringify(body);
    const timestamp = unixTimeStamp();
    const nonce = randomStr();
    const signature = this.buildMessageSign("POST", urlExclueOrigin(apiUrl), timestamp, nonce, json);
    const Authorization = this.getAuthorization(nonce, timestamp, signature);
    const formData = new (0, _formdata2.default)();
    formData.append("meta", json, {
      contentType: "application/json"
    });
    formData.append("file", file, {
      filename: realyFileName
    });
    const res = await this.request.post(apiUrl, formData, {
      headers: {
        Authorization,
        "Content-Type": "multipart/form-data;boundary=" + formData.getBoundary()
      }
    });
    return res.data;
  }
  /**
   * 图片上传
   * @maxSize 2M
   * @param pathOrUrl 图片路径可以是本地路径,也可以是网络路径
   * @param fileName 商户上传的媒体图片的名称，商户自定义，必须以jpg、bmp、png为后缀,不区分大小写。
   * @description 部分微信支付业务指定商户需要使用图片上传 API来上报图片信息，从而获得必传参数的值：图片MediaID 。
   * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter2_1_1.shtml
   */
  async uploadImage(pathOrUrl, fileName) {
    if (isUrl(pathOrUrl)) {
      const { filePath } = await this.downloadFile(pathOrUrl);
      const result = await this._upload(filePath, { fileName, type: "image" });
      _fs.unlink.call(void 0, filePath, (e) => {
        if (e)
          console.error("\u672C\u5730\u6587\u4EF6\u5220\u9664\u5931\u8D25", e);
      });
      return result;
    } else {
      return this._upload(pathOrUrl, { fileName, type: "image" });
    }
  }
  /**
   * 视频上传
   * @maxSize 5M
   * @param pathOrUrl 视频路径可以是本地路径,也可以是网络路径
   * @param fileName 商户上传的媒体视频的名称，商户自定义，必须以avi、wmv、mpeg、mp4、mov、mkv、flv、f4v、m4v、rmvb为后缀,不区分大小写。
   * @description 部分微信支付业务指定商户需要使用视频上传 API来上报视频信息，从而获得必传参数的值：视频MediaID 。
   * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter2_1_2.shtml
   */
  async uploadVideo(pathOrUrl, fileName) {
    if (isUrl(pathOrUrl)) {
      const { filePath } = await this.downloadFile(pathOrUrl);
      const result = this._upload(filePath, { fileName, type: "video" });
      _fs.unlink.call(void 0, filePath, (e) => {
        if (e)
          console.error("\u672C\u5730\u6587\u4EF6\u5220\u9664\u5931\u8D25", e);
      });
      return result;
    } else {
      return this._upload(pathOrUrl, { fileName, type: "video" });
    }
  }
}, _class);
var baseInstanceMap = /* @__PURE__ */ new Map();
var useInstanceMap = /* @__PURE__ */ new Map();
function apiContainer(options, events) {
  const { singleton = true, ...wechatPayOptions } = options;
  let base;
  if (singleton) {
    const key = wechatPayOptions.mchid;
    if (baseInstanceMap.has(key)) {
      base = baseInstanceMap.get(key);
    } else {
      base = new WechatPayV3Base(wechatPayOptions, events);
      baseInstanceMap.set(key, base);
    }
  } else {
    base = new WechatPayV3Base(wechatPayOptions, events);
  }
  function use(ApiClass) {
    if (singleton) {
      const key = ApiClass.name + wechatPayOptions.mchid;
      if (useInstanceMap.has(key)) {
        return useInstanceMap.get(key);
      } else {
        const instance = new ApiClass(base);
        useInstanceMap.set(key, instance);
        return instance;
      }
    }
    return new ApiClass(base);
  }
  const {
    downloadFile,
    publicEncrypt,
    publicEncryptObjectPaths,
    uploadImage,
    uploadVideo,
    aesGcmDecrypt,
    sha256WithRSA,
    sha256WithRsaVerify,
    handleCallback,
    resVerify,
    setEvents
  } = base;
  return {
    use,
    downloadFile: downloadFile.bind(base),
    publicEncrypt: publicEncrypt.bind(base),
    publicEncryptObjectPaths: publicEncryptObjectPaths.bind(base),
    uploadImage: uploadImage.bind(base),
    uploadVideo: uploadVideo.bind(base),
    sha256WithRSA: sha256WithRSA.bind(base),
    aesGcmDecrypt: aesGcmDecrypt.bind(base),
    sha256WithRsaVerify: sha256WithRsaVerify.bind(base),
    handleCallback: handleCallback.bind(base),
    resVerify: resVerify.bind(base),
    setEvents: setEvents.bind(base),
    base
  };
}
function getInstances() {
  return {
    baseInstanceMap,
    useInstanceMap
  };
}

// src/apis/applyment/applyment.ts
var Applyment = class {
  constructor(base) {
    this.base = base;
  }
  /**
   * 提交申请单
   * @notAutoEncrypt <不自动加密>
   * @description 上传图片接口,this.uploadImage
   * @description 加密接口,this.publicEncryptObjectPaths 或者 this.privateEncrypt
   * @param body 请求主体,此接口及其复杂,提供得类型仅作参考,请参考官方文档
   * @doc https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter11_1_1.shtml
   */
  async submitApplications(body) {
    const apiUrl = "https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/";
    const res = await this.base.request.post(apiUrl, body, {
      headers: {
        "Wechatpay-Serial": this.base.certificates[0].serial_no
      }
    });
    return res.data;
  }
  /**
   * 查询申请单状态
   * @param businessCode 业务申请编号
   */
  async queryApplymentState(businessCode) {
    const apiUrl = `https://api.mch.weixin.qq.com/v3/applyment4sub/applyment/business_code/${businessCode}`;
    const res = await this.base.request.get(apiUrl);
    return res.data;
  }
  /**
   * 修改结算账户
   * @param sub_mchid 子商户号 特殊规则：长度最小8个字节。
   * @param body 请求主体
   * @returns 是否成功
   */
  async modifySettlementAccount(sub_mchid, body) {
    const apiUrl = `https://api.mch.weixin.qq.com/v3/apply4sub/sub_merchants/${sub_mchid}/modify-settlement`;
    const res = await this.base.request.post(
      apiUrl,
      this.base.publicEncryptObjectPaths(body, ["account_name", "account_number"])
    );
    return +res.status === 204;
  }
  /**
   * 查询结算账号
   * @param sub_mchid 子商户号 特殊规则：长度最小8个字节。
   * @returns 结算账号信息
   */
  async querySettlementAccount(sub_mchid) {
    const apiUrl = `https://api.mch.weixin.qq.com/v3/apply4sub/sub_merchants/${sub_mchid}/settlement`;
    const res = await this.base.request.get(apiUrl);
    return res.data;
  }
};

// src/apis/basePay/basePay.ts
var UrlMap = {
  order: {
    provider: `https://api.mch.weixin.qq.com/v3/pay/partner/transactions/jsapi`,
    business: `https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi`
  },
  transactionIdQueryOrder: {
    provider: "https://api.mch.weixin.qq.com/v3/pay/partner/transactions/id/{transaction_id}",
    business: "https://api.mch.weixin.qq.com/v3/pay/transactions/id/{transaction_id}"
  },
  outTradeNoQueryOrder: {
    provider: "https://api.mch.weixin.qq.com/v3/pay/partner/transactions/out-trade-no/{out_trade_no}",
    business: "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{out_trade_no}"
  },
  closeOrder: {
    provider: "https://api.mch.weixin.qq.com/v3/pay/partner/transactions/out-trade-no/{out_trade_no}/close",
    business: "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{out_trade_no}/close"
  },
  refund: {
    apiUrl: "https://api.mch.weixin.qq.com/v3/refund/domestic/refunds"
    //退款都是一个
  },
  queryRefund: {
    apiUrl: "https://api.mch.weixin.qq.com/v3/refund/domestic/refunds/{out_refund_no}"
    //查询退款都是一个
  },
  applyTradeBill: {
    apiUrl: "https://api.mch.weixin.qq.com/v3/bill/tradebill"
  },
  fundflowBill: {
    apiUrl: "https://api.mch.weixin.qq.com/v3/bill/fundflowbill"
  },
  subFundflowBill: {
    apiUrl: "https://api.mch.weixin.qq.com/v3/bill/sub-merchant-fundflowbill"
  }
};
var BasePay = class {
  constructor(base) {
    this.base = base;
  }
  //=========================================下单
  async _order(data) {
    const isBusiness = data.appid !== void 0;
    const apiUrl = isBusiness ? UrlMap.order.business : UrlMap.order.provider;
    const result = await this.base.request.post(apiUrl, data);
    return result.data;
  }
  /** 下单-直连商户 */
  async order(data) {
    return this._order(data);
  }
  /** 下单-服务商 */
  async orderOnProvider(data) {
    return this._order(data);
  }
  //=========================================查询订单_通过微信订单号
  async _transactionIdQueryOrder(data) {
    const { transaction_id, ...query } = data;
    const isBusiness = data.mchid !== void 0;
    const _ = isBusiness ? UrlMap.transactionIdQueryOrder.business + "?mchid=" + query.mchid : UrlMap.transactionIdQueryOrder.provider + "?sp_mchid=" + query.sp_mchid + "&sub_mchid=" + query.sub_mchid;
    const apiUrl = replaceTagText(_, {
      transaction_id
    });
    const result = await this.base.request.get(apiUrl);
    return result.data;
  }
  /**
   * 查询订单-通过微信订单号
   */
  async transactionIdQueryOrder(data) {
    return this._transactionIdQueryOrder(data);
  }
  /**
   * 查询订单-服务商-通过微信订单号
   */
  async transactionIdQueryOrderOnProvider(data) {
    return this._transactionIdQueryOrder(data);
  }
  //=========================================查询订单_通过商户订单号
  async _outTradeNoQueryOrder(data) {
    const { out_trade_no, ...query } = data;
    const isBusiness = data.mchid !== void 0;
    const _ = isBusiness ? UrlMap.outTradeNoQueryOrder.business + "?mchid=" + query.mchid : UrlMap.outTradeNoQueryOrder.provider + "?sp_mchid=" + query.sp_mchid + "&sub_mchid=" + query.sub_mchid;
    const apiUrl = replaceTagText(_, {
      out_trade_no
    });
    const result = await this.base.request.get(apiUrl);
    return result.data;
  }
  /**
   * 查询订单-通过商户订单号
   */
  async outTradeNoQueryOrder(data) {
    return this._outTradeNoQueryOrder(data);
  }
  /**
   * 查询订单-服务商-通过商户订单号
   */
  async outTradeNoQueryOrderOnProvider(data) {
    return this._outTradeNoQueryOrder(data);
  }
  //=========================================关闭订单
  async _closeOrder(data) {
    const { out_trade_no, ...body } = data;
    const isBusiness = data.mchid !== void 0;
    const _ = isBusiness ? UrlMap.closeOrder.business : UrlMap.closeOrder.provider;
    const apiUrl = replaceTagText(_, {
      out_trade_no
    });
    const result = await this.base.request.post(apiUrl, body);
    return result.status;
  }
  /**
   * 关闭订单-直连商户
   * @returns status 如果为204,则关闭成功
   */
  async closeOrder(data) {
    return this._closeOrder(data);
  }
  /**
   * 关闭订单-服务商
   * @returns status 如果为204,则关闭成功
   */
  async closeOrderOnProvider(data) {
    return this._closeOrder(data);
  }
  //=========================================退款
  async _refund(data) {
    const { apiUrl } = UrlMap.refund;
    const result = await this.base.request.post(apiUrl, data);
    return result.data;
  }
  /**
   * 退款-直连商户
   */
  async refund(data) {
    return this._refund(data);
  }
  /**
   * 退款-服务商
   */
  async refundOnProvider(data) {
    return this._refund(data);
  }
  //=========================================查询退款
  async _queryRefund(data) {
    const { out_refund_no, sub_mchid } = data;
    let apiUrl = replaceTagText(UrlMap.queryRefund.apiUrl, {
      out_refund_no
    });
    if (sub_mchid) {
      apiUrl += `?sub_mchid=${sub_mchid}`;
    }
    const result = await this.base.request.get(apiUrl);
    return result.data;
  }
  /**
   * 查询退款-直连商户
   */
  async queryRefund(data) {
    return this._queryRefund(data);
  }
  /**
   * 查询退款-服务商
   */
  async queryRefundOnProvider(data) {
    return this._queryRefund(data);
  }
  //=========================================申请交易账单
  async _applyTradeBill(data) {
    let { apiUrl } = UrlMap.applyTradeBill;
    apiUrl += `?bill_date=${data.bill_date}&sub_mchid=${data.sub_mchid}&bill_type=${data.bill_type}&tar_type=${data.tar_type}`;
    const result = await this.base.request.get(apiUrl);
    return result.data;
  }
  /**
   * 申请交易账单-直连商户
   */
  async applyTradeBill(data) {
    return this._applyTradeBill(data);
  }
  /**
   * 申请交易账单-服务商
   */
  async applyTradeBillOnProvider(data) {
    return this._applyTradeBill(data);
  }
  //=========================================申请资金账单
  async _applyFundFlowBill(data) {
    const { apiUrl } = UrlMap.fundflowBill;
    const result = await this.base.request.get(apiUrl, {
      params: data
    });
    return result.data;
  }
  /**
   * 申请资金账单-直连商户
   */
  async applyFundFlowBill(data) {
    return this._applyFundFlowBill(data);
  }
  /**
   * 申请资金账单-服务商
   */
  async applyFundFlowBillOnProvider(data) {
    return this._applyFundFlowBill(data);
  }
  //=========================================申请单个子商户资金账单
  /**
   * 申请单个子商户资金账单 仅限服务商
   */
  async applySubMerchantFundFlowBill(data) {
    const { apiUrl } = UrlMap.subFundflowBill;
    const result = await this.base.request.get(apiUrl, {
      params: data
    });
    return result.data;
  }
  //=========================================下载账单
  /**
   * 下载账单(通用)
   */
  async downloadBill(download_url) {
    const result = await this.base.request.get(download_url, {
      responseType: "arraybuffer"
    });
    return result.data;
  }
};

// src/apis/basePay/AppPay.ts
var UrlMap2 = {
  order: {
    provider: `https://api.mch.weixin.qq.com/v3/pay/partner/transactions/app`,
    business: `https://api.mch.weixin.qq.com/v3/pay/transactions/app`
  }
};
var AppPay = class extends BasePay {
  constructor(base) {
    super(base);
  }
  async _exOrder(params) {
    const isBusiness = params.appid !== void 0;
    const apiUrl = isBusiness ? UrlMap2.order.business : UrlMap2.order.provider;
    const result = await this.base.request.post(apiUrl, params);
    return result.data;
  }
  /**
   * App支付下单 直连
   */
  async order(params) {
    return this._exOrder(params);
  }
  /**
   * App支付下单 服务商
   */
  async orderOnProvider(data) {
    return this._exOrder(data);
  }
  /**
   * 获取App调起支付参数
   * @param params
   * @returns
   */
  getPayParams(params) {
    const { appId, prepay_id, partnerId } = params;
    const timeStamp = unixTimeStamp();
    const nonceStr = randomStr();
    const packageStr = `Sign=WXPay`;
    const message = [appId, timeStamp, nonceStr, prepay_id].join("\n") + "\n";
    const paySign = this.base.sha256WithRSA(message);
    return {
      appId,
      partnerId,
      prepayId: prepay_id,
      package: packageStr,
      nonceStr,
      timeStamp,
      sign: paySign
    };
  }
};

// src/apis/basePay/JSPay.ts
var JSPay = class extends BasePay {
  order(data) {
    return super._order(data);
  }
  orderOnProvider(data) {
    return super._order(data);
  }
  /**
   * 获取调起支付参数
   * @param params
   * @returns
   */
  getPayParams(params) {
    const { appId, prepay_id } = params;
    const timeStamp = unixTimeStamp();
    const nonceStr = randomStr();
    const packageStr = `prepay_id=${prepay_id}`;
    const message = [appId, timeStamp, nonceStr, packageStr].join("\n") + "\n";
    const paySign = this.base.sha256WithRSA(message);
    return {
      appId,
      timeStamp,
      nonceStr,
      package: packageStr,
      signType: "RSA",
      paySign
    };
  }
};

// src/apis/basePay/MiniProgramPay.ts
var MiniProgramPay = class extends BasePay {
  order(data) {
    return super._order(data);
  }
  orderOnProvider(data) {
    return super._order(data);
  }
  /**
   * 获取调起支付参数
   * @param params
   * @returns
   */
  getPayParams(params) {
    const { appId, prepay_id } = params;
    const timeStamp = unixTimeStamp();
    const nonceStr = randomStr();
    const packageStr = `prepay_id=${prepay_id}`;
    const message = [appId, timeStamp, nonceStr, packageStr].join("\n") + "\n";
    const paySign = this.base.sha256WithRSA(message);
    return {
      timeStamp,
      nonceStr,
      package: packageStr,
      signType: "RSA",
      paySign
    };
  }
};

// src/apis/basePay/NativePay.ts
var UrlMap3 = {
  order: {
    provider: `https://api.mch.weixin.qq.com/v3/pay/partner/transactions/native`,
    business: `https://api.mch.weixin.qq.com/v3/pay/transactions/native`
  }
};
var NativePay = class extends BasePay {
  constructor(base) {
    super(base);
  }
  async _exOrder(params) {
    const isBusiness = params.appid !== void 0;
    const apiUrl = isBusiness ? UrlMap3.order.business : UrlMap3.order.provider;
    const result = await this.base.request.post(apiUrl, params);
    return result.data;
  }
  /**
   * Native支付下单 直连
   */
  async order(params) {
    return this._exOrder(params);
  }
  /**
   * Native支付下单 服务商
   */
  async orderOnProvider(data) {
    return this._exOrder(data);
  }
};

// src/apis/basePay/basePay.types.ts
var TradeTypeEnum = /* @__PURE__ */ ((TradeTypeEnum2) => {
  TradeTypeEnum2["JSAPI"] = "JSAPI";
  TradeTypeEnum2["NATIVE"] = "NATIVE";
  TradeTypeEnum2["APP"] = "APP";
  TradeTypeEnum2["MICROPAY"] = "MICROPAY";
  TradeTypeEnum2["MWEB"] = "MWEB";
  TradeTypeEnum2["FACEPAY"] = "FACEPAY";
  return TradeTypeEnum2;
})(TradeTypeEnum || {});
var TradeStateEnum = /* @__PURE__ */ ((TradeStateEnum2) => {
  TradeStateEnum2["SUCCESS"] = "SUCCESS";
  TradeStateEnum2["REFUND"] = "REFUND";
  TradeStateEnum2["NOTPAY"] = "NOTPAY";
  TradeStateEnum2["CLOSED"] = "CLOSED";
  TradeStateEnum2["REVOKED"] = "REVOKED";
  TradeStateEnum2["USERPAYING"] = "USERPAYING";
  TradeStateEnum2["PAYERROR"] = "PAYERROR";
  return TradeStateEnum2;
})(TradeStateEnum || {});
var ResultRefundStatusEnum = /* @__PURE__ */ ((ResultRefundStatusEnum2) => {
  ResultRefundStatusEnum2["SUCCESS"] = "SUCCESS";
  ResultRefundStatusEnum2["CLOSED"] = "CLOSED";
  ResultRefundStatusEnum2["PROCESSING"] = "PROCESSING";
  ResultRefundStatusEnum2["ABNORMAL"] = "ABNORMAL";
  return ResultRefundStatusEnum2;
})(ResultRefundStatusEnum || {});
var ResultRefundChannelEnum = /* @__PURE__ */ ((ResultRefundChannelEnum2) => {
  ResultRefundChannelEnum2["ORIGINAL"] = "ORIGINAL";
  ResultRefundChannelEnum2["BALANCE"] = "BALANCE";
  ResultRefundChannelEnum2["OTHER_BALANCE"] = "OTHER_BALANCE";
  ResultRefundChannelEnum2["OTHER_BANKCARD"] = "OTHER_BANKCARD";
  return ResultRefundChannelEnum2;
})(ResultRefundChannelEnum || {});
var ResultFundsAccountEnum = /* @__PURE__ */ ((ResultFundsAccountEnum2) => {
  ResultFundsAccountEnum2["UNSETTLED"] = "UNSETTLED";
  ResultFundsAccountEnum2["AVAILABLE"] = "AVAILABLE";
  ResultFundsAccountEnum2["UNAVAILABLE"] = "UNAVAILABLE";
  ResultFundsAccountEnum2["OPERATION"] = "OPERATION";
  ResultFundsAccountEnum2["BASIC"] = "BASIC";
  return ResultFundsAccountEnum2;
})(ResultFundsAccountEnum || {});

// src/apis/basePay/h5Pay.ts
var UrlMap4 = {
  order: {
    provider: `https://api.mch.weixin.qq.com/v3/pay/partner/transactions/h5`,
    business: `https://api.mch.weixin.qq.com/v3/pay/transactions/h5`
  }
};
var H5Pay = class extends BasePay {
  constructor(base) {
    super(base);
  }
  async _exOrder(params) {
    const isBusiness = params.appid !== void 0;
    const apiUrl = isBusiness ? UrlMap4.order.business : UrlMap4.order.provider;
    const result = await this.base.request.post(apiUrl, params);
    return result.data;
  }
  /**
   * H5支付下单 直连
   */
  async order(params) {
    return this._exOrder(params);
  }
  /**
   * H5支付下单 服务商
   */
  async orderOnProvider(data) {
    return this._exOrder(data);
  }
};
































exports.AppPay = AppPay; exports.Applyment = Applyment; exports.BasePay = BasePay; exports.H5Pay = H5Pay; exports.JSPay = JSPay; exports.MiniProgramPay = MiniProgramPay; exports.NativePay = NativePay; exports.ResultFundsAccountEnum = ResultFundsAccountEnum; exports.ResultRefundChannelEnum = ResultRefundChannelEnum; exports.ResultRefundStatusEnum = ResultRefundStatusEnum; exports.TradeStateEnum = TradeStateEnum; exports.TradeTypeEnum = TradeTypeEnum; exports.WechatPayV3Base = WechatPayV3Base; exports.apiContainer = apiContainer; exports.decryptToString_AES = decryptToString_AES; exports.encrypt = encrypt; exports.fileSha256 = fileSha256; exports.getCertificatePublicKey = getCertificatePublicKey; exports.getCertificateSerialNo = getCertificateSerialNo; exports.getInstances = getInstances; exports.getPathValue = getPathValue; exports.getPublicKey = getPublicKey; exports.getSysTmpDir = getSysTmpDir; exports.getToken = getToken; exports.isUrl = isUrl; exports.path2FileName = path2FileName; exports.randomStr = randomStr; exports.replaceTagText = replaceTagText; exports.setPathValue = setPathValue; exports.unixTimeStamp = unixTimeStamp; exports.urlExclueOrigin = urlExclueOrigin;
