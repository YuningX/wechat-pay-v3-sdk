import { InternalAxiosRequestConfig, AxiosInstance } from 'axios';
import { KeyObject } from 'crypto';

interface UploadImageResult {
    media_id: string;
}
/**
 * 加密证书对象
 */
interface EncryptCertificate {
    /** ciphertext应用的加密算法 */
    algorithm: string;
    /** 加密使用的随机串 */
    nonce: string;
    /** 加密使用的附加数据 */
    associated_data: string;
    /** 密文 */
    ciphertext: string;
}
/**
 * 证书
 */
interface Certificate {
    /** 证书序列号 */
    serial_no: string;
    /** 证书有效期起始时间 */
    effective_time: string;
    /** 证书有效期截止时间 */
    expire_time: string;
    /** 加密后的证书 */
    encrypt_certificate: EncryptCertificate;
}
/**
 * 附带解密后的证书
 */
interface DecryptCertificates {
    /** 证书序列号 */
    serial_no: string;
    /** 证书有效期起始时间 */
    effective_time: string;
    /** 证书有效期截止时间 */
    expire_time: string;
    /** 解密后的证书 */
    certificate: string;
    /** 证书上的公钥 */
    publicKey: KeyObject;
}
/**
 * 证书列表
 */
type Certificates = Certificate[];
/**
 * 获取证书列表返回结果
 */
type GetCertificatesResult = {
    data: Certificates;
};

interface WechatBaseOptions {
    /**
     * 商户号
     */
    mchid: string;
    /**
     * pem证书
     */
    apiclient_cret: Buffer;
    /**
     * pem私钥
     */
    apiclient_key: Buffer;
    /**
     * apiV3密钥
     */
    apiV3Key: string;
    /**
     * header中的User-Agent
     */
    userAgent?: string;
    /**
     * 自动更新平台证书
     * @default true
     * @description 更偏向于惰性更新,缓存证书并记录过期时间,在每次请求时,比对时间进行更新(简单的时间比对于性能没有啥影响)。
     * @description 如果你需要自己管控,可以关闭此选项,调用updateCertificates(true)方法强制更新实例上的证书
     */
    autoUpdateCertificates?: boolean;
    /**
     * 下载文件文件夹
     * @default [systemTempDir]/wxpay-v3-downloads
     * @description 让部分接口更加方便,例如上传文件给微信接口只能从本地上传
     * @description 需要注意的是,sdk并不会保存此文件,于对应功能完毕后
     */
    downloadDir?: string;
}
interface WechatBaseEventOPtions {
    /**
     * 在请求前触发,可以在此处修改请求配置.
     * @description 签名生成在onRequsetBefore之后,此处无法获取到签名
     * @param config 请求的配置
     * @param instance 当前实例
     */
    onRequsetBefore?: (config: InternalAxiosRequestConfig<any>, instance: WechatPayV3Base) => void;
    /**
     * 在请求后触发
     * @description 签名生成在onRequsetAfter之前,此处可以获取到签名并修改
     * @param config 请求的配置
     * @param instance 当前实例
     */
    onRequsetAfter?: (config: InternalAxiosRequestConfig<any>, instance: WechatPayV3Base) => void;
    /**
     * 在请求成功后触发
     */
    onResponse?: (result: any, instance: WechatPayV3Base) => void;
}
/** 微信支付v3 */
declare class WechatPayV3Base {
    private events;
    /** pem私钥 */
    readonly privateKey: Buffer;
    /** 加密算法,固定值'WECHATPAY2-SHA256-RSA2048'.国密暂不支持 */
    readonly schema = "WECHATPAY2-SHA256-RSA2048";
    /** axios请求示例 */
    readonly request: AxiosInstance;
    /** 商户号 */
    readonly mchid: string;
    /** header -> userAgent (微信可能会拒绝不带userAgent的请求) */
    readonly userAgent: string;
    /** apiV3密钥 */
    readonly apiV3Key: string;
    /** 平台证书列表 */
    certificates: DecryptCertificates[];
    /** 更新证书时间+12小时后的结果,注意此时间并非平台证书本身的过期时间,而是需要更新的时间 */
    certExpiresTime?: Date;
    /** 商户Api证书序列号 */
    readonly apiCretSerialNo: string;
    /** 下载文件文件夹 */
    readonly downloadDir: string;
    constructor(options: WechatBaseOptions, events?: WechatBaseEventOPtions);
    /**
     * 初始化
     */
    private init;
    setEvents(events: WechatBaseEventOPtions): void;
    /**
     * 更新平台证书
     * @description 会判断缓存是否过期,如果过期则更新,否则不更新.
     * @param forceUpdate 强制更新
     */
    updateCertificates(forceUpdate?: boolean): Promise<void>;
    /**
     * 构造签名串并签名
     * @param method 请求方法
     * @param url 请求URL
     * @param timestamp 时间戳
     * @param nonce 随机字符串
     * @param body 请求主体
     */
    protected buildMessageSign(method: string, url: string, timestamp: string, nonce: string, body: string | object): string;
    /**
     * 构造验签名串
     * @param timestamp 参数在响应头中对应
     * @param nonce 参数在响应头中对应
     * @param body 参数在响应头中对应
     * @returns
     */
    protected buildMessageVerify(timestamp: string, nonce: string, body: string): string;
    /**
     * 构造Authorization
     * @param nonce_str 随机字符串
     * @param timestamp 时间戳
     * @param signature 签名(buildMessage生成)
     */
    protected getAuthorization(nonce_str: string, timestamp: string, signature: string): string;
    /**
     * 私钥签名
     * @param data 待签名数据
     * @returns base64编码的签名
     */
    sha256WithRSA(data: string): string;
    /**
     * 平台证书公钥验签
     * @param serial 证书序列号
     * @param signature 签名
     * @param data 待验签数据
     */
    sha256WithRsaVerify(serial: string, signature: string, data: string): boolean;
    /**
     * 解密平台响应
     * @param nonce 随机字符串
     * @param associated_data 附加数据
     * @param ciphertext  密文
     * @returns
     */
    aesGcmDecrypt(options: {
        ciphertext: string;
        nonce: string;
        associated_data: string;
    }): string;
    /**
     * 平台证书公钥加密,如果需要同时加密多个字段,请使用publicEncryptObjectPaths
     * @param data 待加密数据
     * @returns
     */
    publicEncrypt(data: string): string;
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
    publicEncryptObjectPaths<T extends Record<string, any>>(data: T, paths: string[]): any;
    /**
     * 下载文件
     * @param url
     * @param fileName 提供文件名,包括后缀。如果不提供,则从url中获取文件名
     * @returns
     */
    downloadFile(url: string, fileName?: string): Promise<{
        filePath: string;
        fileName: string;
    }>;
    /**
     * 响应验签
     * @description 该函数会验证签名,返回true表示验签成功,返回false表示验签失败
     * @param headers 请求头
     * @param body  请求体
     */
    resVerify<H extends Record<string, any>, B extends Record<string, any>>(headers: H, body?: B): boolean;
    /**
     * 处理回调 -验证签名,并使用AEAD_AES_256_GCM解密
     * @param headers
     * @param body
     */
    handleCallback<H extends Record<string, any>, B extends Record<string, any>>(headers: H, body: B): Promise<B & {
        resource: any;
    }>;
    /**
     * 获取证书
     * @description 获取商户当前可用的平台证书列表。
     * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/wechatpay5_1.shtml
     */
    getCertificates(): Promise<DecryptCertificates[]>;
    private _upload;
    /**
     * 图片上传
     * @maxSize 2M
     * @param pathOrUrl 图片路径可以是本地路径,也可以是网络路径
     * @param fileName 商户上传的媒体图片的名称，商户自定义，必须以jpg、bmp、png为后缀,不区分大小写。
     * @description 部分微信支付业务指定商户需要使用图片上传 API来上报图片信息，从而获得必传参数的值：图片MediaID 。
     * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter2_1_1.shtml
     */
    uploadImage(pathOrUrl: string, fileName?: string): Promise<UploadImageResult>;
    /**
     * 视频上传
     * @maxSize 5M
     * @param pathOrUrl 视频路径可以是本地路径,也可以是网络路径
     * @param fileName 商户上传的媒体视频的名称，商户自定义，必须以avi、wmv、mpeg、mp4、mov、mkv、flv、f4v、m4v、rmvb为后缀,不区分大小写。
     * @description 部分微信支付业务指定商户需要使用视频上传 API来上报视频信息，从而获得必传参数的值：视频MediaID 。
     * @docUrl https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter2_1_2.shtml
     */
    uploadVideo(pathOrUrl: string, fileName?: string): Promise<UploadImageResult>;
}
interface ContainerOptions extends WechatBaseOptions {
    /**
     * 是否使用单例模式
     * @default true
     */
    singleton?: boolean;
}
/**
 * 实例化Api的容器,默认单例
 * @param options Base的配置
 * @param events Base的事件
 * @returns
 */
declare function apiContainer(options: ContainerOptions, events?: WechatBaseEventOPtions): {
    use: <T extends new (wechatpay: WechatPayV3Base) => any>(ApiClass: T) => InstanceType<T>;
    downloadFile: (url: string, fileName?: string | undefined) => Promise<{
        filePath: string;
        fileName: string;
    }>;
    publicEncrypt: (data: string) => string;
    publicEncryptObjectPaths: <T_1 extends Record<string, any>>(data: T_1, paths: string[]) => any;
    uploadImage: (pathOrUrl: string, fileName?: string | undefined) => Promise<UploadImageResult>;
    uploadVideo: (pathOrUrl: string, fileName?: string | undefined) => Promise<UploadImageResult>;
    sha256WithRSA: (data: string) => string;
    aesGcmDecrypt: (options: {
        ciphertext: string;
        nonce: string;
        associated_data: string;
    }) => string;
    sha256WithRsaVerify: (serial: string, signature: string, data: string) => boolean;
    handleCallback: <H extends Record<string, any>, B extends Record<string, any>>(headers: H, body: B) => Promise<B & {
        resource: any;
    }>;
    resVerify: <H_1 extends Record<string, any>, B_1 extends Record<string, any>>(headers: H_1, body?: B_1 | undefined) => boolean;
    setEvents: (events: WechatBaseEventOPtions) => void;
    base: WechatPayV3Base;
};
/**
 * 查看当前内存中的实例
 */
declare function getInstances(): {
    baseInstanceMap: Map<string, WechatPayV3Base>;
    useInstanceMap: Map<string, any>;
};

interface SubmitApplicationsResult {
    applyment_id: string;
}
type BankAccountType = 'BANK_ACCOUNT_TYPE_CORPORATE' | 'BANK_ACCOUNT_TYPE_PERSONAL';
type ApplymentState = 'APPLYMENT_STATE_EDITTING' | 'APPLYMENT_STATE_AUDITING' | 'APPLYMENT_STATE_REJECTED' | 'APPLYMENT_STATE_TO_BE_CONFIRMED' | 'APPLYMENT_STATE_TO_BE_SIGNED' | 'APPLYMENT_STATE_SIGNING' | 'APPLYMENT_STATE_FINISHED' | 'APPLYMENT_STATE_CANCELED';
interface QueryApplymentStateResult {
    /** 微信支付申请单号 */
    applyment_id: string;
    /** 业务申请编号 */
    business_code: string;
    /** 特约商户号,当申请单状态为APPLYMENT_STATE_FINISHED时才返回*/
    sub_mchid?: string;
    /** 超管签约链接,状态为APPLYMENT_STATE_TO_BE_SIGNED才返回 */
    sign_url?: string;
    /** 申请单状态 */
    applyment_state: ApplymentState;
    /** 申请单状态描述 */
    applyment_state_msg: string;
    /** 审核情况，当申请状态为APPLYMENT_STATE_REJECTED时才返回 */
    audit_detail?: {
        /** 字段名:例如:id_card_copy */
        field: string;
        /** 字段名描述:例如:身份证人像面 */
        field_name: string;
        /** 驳回原因 */
        reject_reason: string;
    }[];
}
interface ModifySettlementAccountBody {
    /** 账户类型 */
    account_type: 'ACCOUNT_TYPE_BUSINESS' | 'ACCOUNT_TYPE_PRIVATE';
    /** 开户名称 */
    account_name?: string;
    /** 开户银行 */
    account_bank: string;
    /** 开户银行省市编码 */
    bank_address_code: string;
    /** 开户银行全称（含支行）  */
    bank_name?: string;
    /** 开户银行联行号  */
    bank_branch_id?: string;
    /** 银行账号 */
    account_number: string;
}
interface QuerySettlementAccountResult {
    /** 账户类型 */
    account_type: 'ACCOUNT_TYPE_BUSINESS' | 'ACCOUNT_TYPE_PRIVATE';
    /** 开户银行 */
    account_bank: string;
    /** 开户银行全称（含支行） */
    bank_name?: string;
    /** 开户银行联行号 */
    bank_branch_id?: string;
    /** 银行账号 */
    account_number: string;
    /** 汇款验证结果 */
    verify_result: 'VERIFYING' | 'VERIFY_SUCCESS' | 'VERIFY_FAIL';
    /** 汇款验证失败原因 */
    verify_fail_reason?: string;
}
interface SubmitApplicationBody {
    /** 业务申请编号 */
    business_code: string;
    /** 超级管理员信息 */
    contact_info: SubmitApplicationContactInfo;
    /** 主体资料 */
    subject_info: SubmitApplicationSubjectInfo;
    /** 经营资料 */
    business_info: SubmitApplicationBusinessInfo;
    /** 结算规则 */
    settlement_info: SubmitApplicationSettlementInfo;
    /** 结算银行账户 */
    bank_account_info: SubmitApplicationBankAccountInfo;
    /** 补充材料 */
    addition_info?: SubmitApplicationAdditionInfo;
}
type ContactType = 'LEGAL' | 'SUPER';
type ContactIdType = 'IDENTIFICATION_TYPE_IDCARD' | 'IDENTIFICATION_TYPE_PASSPORT' | 'IDENTIFICATION_TYPE_OTHERS';
interface SubmitApplicationContactInfo {
    /** 超级管理员类型 */
    contact_type: ContactType;
    /** 超级管理员姓名 */
    contact_name: string;
    /** 超级管理员证件类型 */
    contact_id_type?: ContactIdType;
    /** 超级管理员证件号码 */
    contact_id_number?: string;
    /** 超级管理员证件照片 */
    contact_id_doc_copy?: string;
    /** 超级管理员证件反面照片 */
    contact_id_doc_copy_back?: string;
    /** 超级管理员证件有效期开始时间 */
    contact_period_begin?: string;
    /** 超级管理员证件有效期结束时间 */
    contact_period_end?: string;
    /** 业务办理授权函 */
    business_authorization_letter?: string;
    /** 超级管理员微信OpenID */
    openid?: string;
    /** 联系手机 */
    mobile_phone: string;
    /** 联系邮箱 */
    contact_email: string;
}
interface SubmitApplicationSubjectInfo {
    /** 主体类型 */
    subject_type: SubjectType;
    /** 是否是金融机构 */
    finance_institution?: boolean;
    /** 营业执照 */
    business_license_info?: SubmitApplicationBusinessLicenseInfo;
    /** 登记证书 */
    certificate_info?: SubmitApplicationCertificateInfo;
    /** 单位证明函照片 */
    certificate_letter_copy?: string;
    /** 金融机构许可证信息 */
    finance_institution_info?: SubmitApplicationFinanceInstitutionInfo;
    /** 经营者/法人身份证件 */
    identity_info: SubmitApplicationIdentityInfo;
    /** 最终受益人信息列表(UBO) */
    ubo_info_list?: SubmitApplicationUboInfo[];
}
interface SubmitApplicationBusinessLicenseInfo {
    /** 营业执照照片 */
    license_copy: string;
    /** 注册号/统一社会信用代码 */
    license_number: string;
    /** 商户名称 */
    merchant_name: string;
    /** 个体户经营者/法人姓名 */
    legal_person: string;
    /** 注册地址 */
    license_address?: string;
    /** 有效期限开始日期 */
    period_begin?: string;
    /** 有效期限结束日期 */
    period_end?: string;
}
type CertificateType = 'CERTIFICATE_TYPE_2388' | 'CERTIFICATE_TYPE_2389' | 'CERTIFICATE_TYPE_2394' | 'CERTIFICATE_TYPE_2395' | 'CERTIFICATE_TYPE_2396' | 'CERTIFICATE_TYPE_2520' | 'CERTIFICATE_TYPE_2521' | 'CERTIFICATE_TYPE_2522' | 'CERTIFICATE_TYPE_2399' | 'CERTIFICATE_TYPE_2400';
interface SubmitApplicationCertificateInfo {
    /** 登记证书照片 */
    cert_copy: string;
    /** 登记证书类型 */
    cert_type: CertificateType;
    /** 证书号 */
    cert_number: string;
    /** 商户名称 */
    merchant_name: string;
    /** 注册地址 */
    company_address: string;
    /** 法定代表人 */
    legal_person: string;
    /** 有效期限开始日期 */
    period_begin: string;
    /** 有效期限结束日期 */
    period_end: string;
}
/** 金融机构类型 */
type FinanceType = 'BANK_AGENT' | 'PAYMENT_AGENT' | 'INSURANCE' | 'TRADE_AND_SETTLE' | 'OTHER';
interface SubmitApplicationFinanceInstitutionInfo {
    /** 金融机构类型 */
    finance_type: FinanceType;
    /** 金融机构许可证图片 */
    finance_license_pics: string[];
}
type IdHolderType = 'LEGAL' | 'SUPER';
type IdDocType = 'IDENTIFICATION_TYPE_IDCARD' | 'IDENTIFICATION_TYPE_OVERSEA_PASSPORT' | 'IDENTIFICATION_TYPE_HONGKONG_PASSPORT' | 'IDENTIFICATION_TYPE_MACAO_PASSPORT' | 'IDENTIFICATION_TYPE_TAIWAN_PASSPORT' | 'IDENTIFICATION_TYPE_FOREIGN_RESIDENT' | 'IDENTIFICATION_TYPE_HONGKONG_MACAO_RESIDENT' | 'IDENTIFICATION_TYPE_TAIWAN_RESIDENT';
type IdCardInfo = {
    /** 身份证人像面照片 */
    id_card_copy: string;
    /** 身份证国徽面照片 */
    id_card_national: string;
    /** 身份证姓名 */
    id_card_name: string;
    /** 身份证号码 */
    id_card_number: string;
    /** 身份证居住地址 */
    id_card_address?: string;
    /** 身份证有效期开始时间 */
    card_period_begin: string;
    /** 身份证有效期结束时间 */
    card_period_end: string;
};
interface IdDocInfo {
    /** 证件正面照片 */
    id_doc_copy: string;
    /** 证件反面照片 */
    id_doc_copy_back?: string;
    /** 证件姓名 */
    id_doc_name: string;
    /** 证件号码 */
    id_doc_number: string;
    /** 证件居住地址 */
    id_doc_address?: string;
    /** 证件有效期开始时间 */
    doc_period_begin: string;
    /** 证件有效期结束时间 */
    doc_period_end: string;
}
interface SubmitApplicationIdentityInfo {
    /** 证件持有人类型 */
    id_holder_type?: IdHolderType;
    /** 证件类型 */
    id_doc_type?: IdDocType;
    /** 法定代表人说明函 */
    authorize_letter_copy?: string;
    /** 身份证信息 */
    id_card_info?: IdCardInfo;
    /** 其他类型证件信息 */
    id_doc_info?: IdDocInfo;
    /** 经营者/法人是否为受益人 */
    owner?: boolean;
}
/**
 *  UBO信息 估计用的不多,就any了。
 *  https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter11_1_1.shtml
 */
type SubmitApplicationUboInfo = any;
/** 主体类型 */
type SubjectType = 'SUBJECT_TYPE_INDIVIDUAL' | 'SUBJECT_TYPE_ENTERPRISE' | 'SUBJECT_TYPE_GOVERNMENT' | 'SUBJECT_TYPE_INSTITUTIONS' | 'SUBJECT_TYPE_OTHERS';
interface SubmitApplicationBusinessInfo {
    /** 商户简称 */
    merchant_shortname: string;
    /** 客服电话 */
    service_phone: string;
    /** 经营场景 */
    sales_info: {
        /** 经营场景类型 */
        sales_scenes_type: SalesScenesType[];
        /** 线下场所 */
        biz_store_info?: BizStoreInfo;
        /** 公众号 */
        mp_info?: MpInfo;
        /** 小程序 */
        mini_program_info?: MiniProgramInfo;
        /** APP */
        app_info?: AppInfo;
        /** Web */
        web_info?: WebInfo;
        /** 企业微信 */
        wework_info?: WeworkInfo;
    };
}
/** 经营场景类型 */
type SalesScenesType = 'SALES_SCENES_STORE' | 'SALES_SCENES_MP' | 'SALES_SCENES_MINI_PROGRAM' | 'SALES_SCENES_WEB' | 'SALES_SCENES_APP' | 'SALES_SCENES_WEWORK';
interface BizStoreInfo {
    /** 线下场所名称 */
    biz_store_name: string;
    /** 线下场所省市编码 */
    biz_address_code: string;
    /** 线下场所地址 */
    biz_store_address: string;
    /** 线下场所门头照片 */
    store_entrance_pic: string[];
    /** 线下场所内部照片 */
    indoor_pic: string[];
    /** 线下场所对应的商家AppID */
    biz_sub_appid?: string;
}
interface MpInfo {
    /** 服务商公众号AppID */
    mp_appid?: string;
    /** 商家公众号AppID */
    mp_sub_appid?: string;
    /** 公众号页面截图 */
    mp_pics: string[];
}
interface MiniProgramInfo {
    /** 服务商小程序APPID */
    mini_program_appid?: string;
    /** 商家小程序APPID */
    mini_program_sub_appid?: string;
    /** 小程序截图 */
    mini_program_pics?: string[];
}
interface AppInfo {
    /** 服务商应用APPID */
    app_appid?: string;
    /** 商家应用APPID */
    app_sub_appid?: string;
    /** APP截图 */
    app_pics: string[];
}
interface WebInfo {
    /** 互联网网站域名 */
    domain: string;
    /** 网站授权函 */
    web_authorisation?: string;
    /** 互联网网站对应的商家APPID */
    web_appid?: string;
}
interface WeworkInfo {
    /** 商家企业微信CorpID */
    sub_corp_id: string;
    /** 企业微信页面截图 */
    wework_pics: string[];
}
interface SubmitApplicationSettlementInfo {
    /** 入驻结算规则ID */
    settlement_id: string;
    /** 所属行业 */
    qualification_type: string;
    /** 特殊资质图片 */
    qualifications?: string[];
    /** 优惠费率活动ID */
    activities_id?: string;
    /** 优惠费率活动值 */
    activities_rate?: string;
    /** 优惠费率活动补充材料 */
    activities_additions?: string[];
}
interface SubmitApplicationBankAccountInfo {
    /** 账户类型 */
    bank_account_type: BankAccountType;
    /** 开户名称 */
    account_name: string;
    /** 开户银行 */
    account_bank: string;
    /** 开户银行省市编码 */
    bank_address_code: string;
    /** 开户银行联行号 */
    bank_branch_id?: string;
    /** 开户银行全称（含支行） */
    bank_name?: string;
    /** 银行账号 */
    account_number: string;
}
interface SubmitApplicationAdditionInfo {
    /** 法人开户承诺函 */
    legal_person_commitment?: string;
    /** 法人开户意愿视频 */
    legal_person_video?: string;
    /** 补充材料 */
    business_addition_pics?: string[];
    /** 补充说明 */
    business_addition_msg?: string;
}

/**
 * 子商户 (特约商户)
 */
declare class Applyment {
    private base;
    constructor(base: WechatPayV3Base);
    /**
     * 提交申请单
     * @notAutoEncrypt <不自动加密>
     * @description 上传图片接口,this.uploadImage
     * @description 加密接口,this.publicEncryptObjectPaths 或者 this.privateEncrypt
     * @param body 请求主体,此接口及其复杂,提供得类型仅作参考,请参考官方文档
     * @doc https://pay.weixin.qq.com/wiki/doc/apiv3_partner/apis/chapter11_1_1.shtml
     */
    submitApplications(body: SubmitApplicationBody): Promise<SubmitApplicationsResult>;
    /**
     * 查询申请单状态
     * @param businessCode 业务申请编号
     */
    queryApplymentState(businessCode: string): Promise<QueryApplymentStateResult>;
    /**
     * 修改结算账户
     * @param sub_mchid 子商户号 特殊规则：长度最小8个字节。
     * @param body 请求主体
     * @returns 是否成功
     */
    modifySettlementAccount(sub_mchid: string, body: ModifySettlementAccountBody): Promise<boolean>;
    /**
     * 查询结算账号
     * @param sub_mchid 子商户号 特殊规则：长度最小8个字节。
     * @returns 结算账号信息
     */
    querySettlementAccount(sub_mchid: string): Promise<QuerySettlementAccountResult>;
}

interface BaseOrderParams {
    /** 商品描述 */
    description: string;
    /** 商户系统内部订单号，只能是数字、大小写字母_-*且在同一个商户号下唯一 */
    out_trade_no: string;
    /** 订单失效时间，遵循rfc3339标准格式，格式为yyyy-MM-DDTHH:mm:ss+TIMEZONE，yyyy-MM-DD表示年月日，T出现在字符串中，表示time元素的开头，HH:mm:ss表示时分秒，TIMEZONE表示时区（+08:00表示东八区时间，领先UTC8小时，即北京时间）。例如：2015-05-20T13:29:35+08:00表示，北京时间2015年5月20日 13点29分35秒。 */
    time_expire?: string;
    /** 附加数据，在查询API和支付通知中原样返回，可作为自定义参数使用，实际情况下只有支付完成状态才会返回该字段。 */
    attach?: string;
    /** 异步接收微信支付结果通知的回调地址，通知url必须为外网可访问的url，不能携带参数。 公网域名必须为https，如果是走专线接入，使用专线NAT IP或者私有回调域名可使用http */
    notify_url: string;
    /** 订单优惠标记 */
    goods_tag?: string;
    /** 电子发票入口开放标识,传入true时，支付成功消息和支付详情页将出现开票入口。需要在微信支付商户平台或微信公众平台开通电子发票功能，传此字段才可生效。 */
    support_fapiao?: boolean;
    /** 订单金额信息 */
    amount: OrderParamsAmount;
    /** 支付者 */
    payer?: any;
    /** 优惠功能 */
    detail?: OrderParamsDetail;
    /** 支付场景描述 */
    scene_info?: OrderParamsSceneInfo;
    /** 结算信息 */
    settle_info?: OrderParamsSettleInfo;
}
interface OrderParamsAmount {
    /** 总金额,单位为分 */
    total?: number;
    /** 货币类型,默认CNY，境内商户号仅支持人名币 */
    currency?: string;
}
interface OrderParamsDetail {
    /** 商品小票ID */
    invoice_id?: string;
    /** 订单原价 */
    cost_price?: number;
    /** 商品列表 */
    goods_detail?: OrderParamsDetailGoodsDetail[];
}
interface OrderParamsDetailGoodsDetail {
    /** 商品编码 */
    merchant_goods_id: string;
    /** 微信侧商品编码 */
    wechatpay_goods_id?: string;
    /** 商品名称 */
    goods_name: string;
    /** 商品数量 */
    quantity: number;
    /** 商品单价，单位为分 */
    unit_price: number;
}
interface OrderParamsSceneInfo {
    /** 商户端设备号 */
    device_id?: string;
    /** 用户终端ip */
    payer_client_ip: string;
    /** 商户门店信息 */
    store_info: OrderParamsSceneInfoStoreInfo;
}
interface OrderParamsSceneInfoStoreInfo {
    /** 门店编号 */
    id: string;
    /** 门店名称 */
    name?: string;
    /** 门店行政区划码 */
    area_code?: string;
    /** 门店详细地址 */
    address?: string;
}
interface OrderParamsSettleInfo {
    /** 是否指定分账 */
    profit_sharing?: boolean;
}
/**
 * appid && mchid
 */
interface BusinessToken {
    /** 应用ID */
    appid: string;
    /** 直连商户号 */
    mchid: string;
}
/**
 * sp_appid && sp_mchid
 */
interface ProviderToken {
    sp_appid: string;
    sp_mchid: string;
}
/**
 * sub_mchid && [sub_appid]
 */
interface SubToken {
    sub_appid?: string;
    sub_mchid: string;
}
interface BusinessPayerToken {
    openid: string;
}
interface ProviderPayerToken {
    sp_openid?: string;
    sub_openid?: string;
}
interface JSAPIOder_Business extends BaseOrderParams, BusinessToken {
    payer: BusinessPayerToken;
}
interface JSAPIOder_Provider extends BaseOrderParams, ProviderToken, SubToken {
    payer: ProviderPayerToken;
}
interface AppOrder_Business extends Omit<BaseOrderParams, 'payer'>, BusinessToken {
}
interface AppOrder_Provider extends Omit<BaseOrderParams, 'payer'>, ProviderToken, SubToken {
}
interface H5Order_Business extends Omit<BaseOrderParams, 'payer'>, BusinessToken {
}
interface H5Order_Provider extends Omit<BaseOrderParams, 'payer'>, ProviderToken, SubToken {
}
interface NativeOrder_Business extends Omit<BaseOrderParams, 'payer'>, BusinessToken {
}
interface NativeOrder_Provider extends Omit<BaseOrderParams, 'payer'>, ProviderToken, SubToken {
}
type OrderResult = {
    prepay_id: string;
} | {
    h5_url: string;
} | {
    code_url: string;
};
interface BaseQueryOrderWithTid {
    /** 微信支付订单号 */
    transaction_id: string;
}
interface JSAPI_QueryOrder_tid_Business extends BaseQueryOrderWithTid {
    mchid: string;
}
interface JSAPI_QueryOrder_tid_Provider extends BaseQueryOrderWithTid {
    sp_mchid: string;
    sub_mchid: string;
}
interface BaseQueryOrderWithOutTradeNo {
    /** 商户订单号 */
    out_trade_no: string;
}
interface JSAPI_QueryOrder_outTradeNo_Business extends BaseQueryOrderWithOutTradeNo {
    mchid: string;
}
interface JSAPI_QueryOrder_outTradeNo_Provider extends BaseQueryOrderWithOutTradeNo {
    sp_mchid: string;
    sub_mchid: string;
}
interface BaseQueryOrderResult {
    /** 商户订单号 */
    out_trade_no: string;
    /** 微信支付订单号 */
    transaction_id: string;
    /** 交易类型 */
    trade_type: TradeTypeEnum;
    /** 交易状态 */
    trade_state: TradeStateEnum;
    /** 交易状态描述 */
    trade_state_desc: string;
    /** 付款银行 */
    bank_type: string;
    /** 附加数据 */
    attach: string;
    /** 支付完成时间 */
    success_time: string;
    /** 支付者信息 */
    payer?: any;
    /** 订单金额信息 */
    amount?: QueryOrderAmount;
    /** 支付场景描述 */
    scene_info?: {
        /** 商户端设备号 */
        device_id: string;
    };
    /** 优惠功能 */
    promotion_detail?: QueryOrderPromotionDetail[];
}
declare enum TradeTypeEnum {
    /** 公众号支付 */
    JSAPI = "JSAPI",
    /** 扫码支付 */
    NATIVE = "NATIVE",
    /** APP支付 */
    APP = "APP",
    /** 付款码支付 */
    MICROPAY = "MICROPAY",
    /** H5支付 */
    MWEB = "MWEB",
    /** 刷脸支付 */
    FACEPAY = "FACEPAY"
}
declare enum TradeStateEnum {
    /** 支付成功 */
    SUCCESS = "SUCCESS",
    /** 转入退款 */
    REFUND = "REFUND",
    /** 未支付 */
    NOTPAY = "NOTPAY",
    /** 已关闭 */
    CLOSED = "CLOSED",
    /** 已撤销（仅付款码支付会返回） */
    REVOKED = "REVOKED",
    /** 用户支付中（仅付款码支付会返回） */
    USERPAYING = "USERPAYING",
    /** 支付失败（仅付款码支付会返回） */
    PAYERROR = "PAYERROR"
}
interface QueryOrderAmount {
    /** 订单金额 */
    total: number;
    /** 用户支付金额 */
    payer_total: number;
    /** 用户支付币种 */
    payer_currency: string;
    /** 货币类型 */
    currency: string;
}
interface QueryOrderPromotionDetail {
    /** 券ID */
    coupon_id: string;
    /** 优惠名称 */
    name?: string;
    /** 优惠范围 */
    scope?: 'GLOBAL' | 'SINGLE';
    /** 优惠类型 */
    type?: 'CASH' | 'NOCASH';
    /** 优惠券面额 */
    amount: number;
    /** 活动id */
    stock_id?: string;
    /** 微信出资 */
    wechatpay_contribute?: number;
    /** 商户出资 */
    merchant_contribute?: number;
    /** 其他出资 */
    other_contribute?: number;
    /** 优惠币种 */
    currency?: string;
    /** 单品列表 */
    goods_detail?: QueryOrderGoodsDetail[];
}
interface QueryOrderGoodsDetail {
    /** 商品编码 */
    goods_id: string;
    /** 商品数量 */
    quantity: number;
    /** 商品单价 */
    unit_price: number;
    /** 商品优惠金额 */
    discount_amount: number;
    /** 商品备注 */
    goods_remark?: string;
}
interface QueryOrderResult_Business extends BaseQueryOrderResult, BusinessToken {
}
interface QueryOrderResult_Provider extends BaseQueryOrderResult, ProviderToken, SubToken {
}
interface ReqPaymentParams {
    /** appid,若下单时候传了sub_appid,须为sub_appid的值 */
    appId: string;
    /** 预支付订单号,下单接口返回 */
    prepay_id: string;
}
interface AppReqPaymentParams extends ReqPaymentParams {
    /** 商户号,若下单时候传了sub_mchid,须为sub_mchid的值 */
    partnerId: string;
}
interface GoodsDetail {
    /** 商户侧商品编码 */
    merchant_goods_id: string;
    /** 微信侧商品编码 */
    wechatpay_goods_id?: string;
    /** 商品名称 */
    goods_name?: string;
    /** 商品单价 */
    unit_price: number;
    /** 商品退款金额 */
    refund_amount: number;
    /** 商品退款数量 */
    refund_quantity: number;
}
interface RefundAmount {
    /** 订单总金额，单位为分 */
    total: number;
    /** 订单退款金额，单位为分 */
    refund: number;
    /** 货币类型，符合ISO4217标准的三位字母代码，默认人民币：CNY */
    currency: string;
}
interface Refund_Business {
    /** 微信支付订单号 */
    transaction_id?: string;
    /** 商户订单号 */
    out_trade_no?: string;
    /** 商户退款单号 */
    out_refund_no: string;
    /** 退款原因 */
    reason?: string;
    /** 退款结果通知url */
    notify_url?: string;
    /** 资金账户 */
    funds_account?: string;
    /** 退款金额信息 */
    amount: RefundAmount;
    /** 单品列表信息，微信支付后台会根据此参数控制向用户展示商品详情 */
    goods_detail?: GoodsDetail[];
}
interface Refund_Provider extends Refund_Business {
    /** 子商户号，服务商模式下必填 */
    sub_mchid: string;
}
interface RefundResult {
    /** 微信支付退款单号 */
    refund_id: string;
    /** 商户退款单号 */
    out_refund_no: string;
    /** 微信支付订单号 */
    transaction_id: string;
    /** 商户订单号 */
    out_trade_no: string;
    /** 退款渠道 */
    channel: ResultRefundChannelEnum;
    /** 退款入账账户 */
    user_received_account: string;
    /** 退款成功时间 */
    success_time?: string;
    /** 退款创建时间 */
    create_time: string;
    /** 退款状态 */
    status: ResultRefundStatusEnum;
    /** 资金账户 */
    funds_account?: ResultFundsAccountEnum;
    /** 金额信息 */
    amount: ResultRefundAmount;
    /** 优惠退款信息 */
    promotion_detail: any;
}
declare enum ResultRefundStatusEnum {
    /** 退款成功 */
    SUCCESS = "SUCCESS",
    /** 退款关闭 */
    CLOSED = "CLOSED",
    /** 退款处理中 */
    PROCESSING = "PROCESSING",
    /** 退款异常 */
    ABNORMAL = "ABNORMAL"
}
declare enum ResultRefundChannelEnum {
    /** 原路退款 */
    ORIGINAL = "ORIGINAL",
    /** 退回到余额 */
    BALANCE = "BALANCE",
    /** 原账户异常退到其他余额账户 */
    OTHER_BALANCE = "OTHER_BALANCE",
    /** 原银行卡异常退到其他银行卡 */
    OTHER_BANKCARD = "OTHER_BANKCARD"
}
declare enum ResultFundsAccountEnum {
    /** 未结算资金 */
    UNSETTLED = "UNSETTLED",
    /** 可用余额 */
    AVAILABLE = "AVAILABLE",
    /** 不可用余额 */
    UNAVAILABLE = "UNAVAILABLE",
    /** 运营户 */
    OPERATION = "OPERATION",
    /** 基本账户（含可用余额和不可用余额） */
    BASIC = "BASIC"
}
interface ResultRefundAmount {
    /** 订单总金额，单位为分 */
    total: number;
    /** 退款标价金额，单位为分，可以做部分退款 */
    refund: number;
    /** 退款出资的账户类型及金额信息 */
    from?: {
        /** 资金账户类型 */
        account: 'AVAILABLE' | 'UNAVAILABLE';
        /** 退款金额 */
        amount: number;
    }[];
    /** 现金支付金额，单位为分，只能为整数 */
    payer_total: number;
    /** 退款给用户的金额，不包含所有优惠券金额 */
    payer_refund: number;
    /** 去掉非充值代金券退款金额后的退款金额，单位为分，退款金额=申请退款金额-非充值代金券退款金额，退款金额<=申请退款金额 */
    settlement_refund: number;
    /** 应结订单金额=订单金额-免充值代金券金额，应结订单金额<=订单金额，单位为分 */
    settlement_total: number;
    /** 优惠退款金额<=退款金额，退款金额-代金券或立减优惠退款金额为现金，说明详见代金券或立减优惠，单位为分 */
    discount_refund: number;
    /** 退款币种 */
    currency: string;
    /** 手续费退款金额，单位为分 */
    refund_fee?: number;
}
interface ResultPromotionDetail {
    /** 券或者立减优惠id */
    promotion_id: string;
    /** 枚举值：GLOBAL：全场代金券 SINGLE：单品优惠 */
    scope: 'GLOBAL' | 'SINGLE';
    /** 枚举值： COUPON：代金券，需要走结算资金的充值型代金券 DISCOUNT：优惠券，不走结算资金的免充值型优惠券 */
    type: 'COUPON' | 'DISCOUNT';
    /** 用户享受优惠的金额（优惠券面额=微信出资金额+商家出资金额+其他出资方金额 ），单位为分 */
    amount: number;
    /** 优惠退款金额<=退款金额，退款金额-代金券或立减优惠退款金额为用户支付的现金，说明详见代金券或立减优惠，单位为分 */
    refund_amount: number;
    /** 商品列表 */
    goods_detail?: GoodsDetail[];
}
interface TradeBillParams {
    bill_date: string;
    sub_mchid?: string;
    /**
     * ALL：返回当日所有订单信息（不含充值退款订单）
     * SUCCESS：返回当日成功支付的订单（不含充值退款订单）
     * REFUND：返回当日退款订单（不含充值退款订单）
     */
    bill_type?: 'ALL' | 'SUCCESS' | 'REFUND';
    tar_type?: 'GZIP';
}
interface BillResult {
    download_url: string;
    hash_type: 'SHA1';
    hash_value: string;
}
interface FundflowBillParams {
    /** 账单日期，最长支持拉取最近三个月的账单 */
    bill_date: string;
    /** 资金账户类型，BASIC，基本账户，OPERATION，运营账户，FEES，手续费账户 */
    account_type?: 'BASIC' | 'OPERATION' | 'FEES';
    /** 压缩账单,默认数据流 */
    tar_type?: 'GZIP';
}
interface SubMerchantFundflowBillParams {
    /** 账单日期，最长支持拉取最近三个月的账单 */
    bill_date: string;
    /** 资金账户类型，BASIC，基本账户，OPERATION，运营账户，FEES，手续费账户 */
    account_type?: 'BASIC' | 'OPERATION' | 'FEES';
    /** 压缩账单,默认数据流 */
    tar_type?: 'GZIP';
    /** 加密算法 */
    algorithm?: 'AEAD_AES_256_GCM' | 'SM4_GCM';
    /** 子商户号 */
    sub_mchid: string;
}
interface SubMerchantFundflowBillResult {
    download_bill_count: number;
    download_bill_list: {
        /** 账单文件序号 */
        bill_sequence: number;
        /** 下载地址30s内有效 */
        download_url: string;
        /** 加密密钥,加密账单文件使用的加密密钥。密钥用商户证书的公钥进行加密，然后进行Base64编码 */
        encrypt_key: string;
        /** 哈希类型 */
        hash_type: 'SHA1';
        /** 哈希值 */
        hash_value: string;
        /** 随机字符串 */
        nonce: string;
    }[];
}

/**
 * 基础支付
 * 默认以JSAPI接口构成,其他接口可继承此类进行扩展。
 * 除开下单接口,其余接口基本一致
 */
declare class BasePay {
    base: WechatPayV3Base;
    constructor(base: WechatPayV3Base);
    protected _order<T = OrderResult>(data: any): Promise<T>;
    /** 下单-直连商户 */
    order(data: JSAPIOder_Business): Promise<OrderResult>;
    /** 下单-服务商 */
    orderOnProvider(data: JSAPIOder_Provider): Promise<OrderResult>;
    protected _transactionIdQueryOrder<T = any>(data: any): Promise<T>;
    /**
     * 查询订单-通过微信订单号
     */
    transactionIdQueryOrder(data: JSAPI_QueryOrder_tid_Business): Promise<QueryOrderResult_Business>;
    /**
     * 查询订单-服务商-通过微信订单号
     */
    transactionIdQueryOrderOnProvider(data: JSAPI_QueryOrder_tid_Provider): Promise<QueryOrderResult_Provider>;
    _outTradeNoQueryOrder<T = any>(data: any): Promise<T>;
    /**
     * 查询订单-通过商户订单号
     */
    outTradeNoQueryOrder(data: JSAPI_QueryOrder_outTradeNo_Business): Promise<QueryOrderResult_Business>;
    /**
     * 查询订单-服务商-通过商户订单号
     */
    outTradeNoQueryOrderOnProvider(data: JSAPI_QueryOrder_outTradeNo_Provider): Promise<QueryOrderResult_Provider>;
    protected _closeOrder(data: any): Promise<number>;
    /**
     * 关闭订单-直连商户
     * @returns status 如果为204,则关闭成功
     */
    closeOrder(data: JSAPI_QueryOrder_outTradeNo_Business): Promise<number>;
    /**
     * 关闭订单-服务商
     * @returns status 如果为204,则关闭成功
     */
    closeOrderOnProvider(data: JSAPI_QueryOrder_outTradeNo_Provider): Promise<number>;
    protected _refund<T = any>(data: any): Promise<T>;
    /**
     * 退款-直连商户
     */
    refund(data: Refund_Business): Promise<RefundResult>;
    /**
     * 退款-服务商
     */
    refundOnProvider(data: Refund_Provider): Promise<RefundResult>;
    protected _queryRefund<T = any>(data: any): Promise<T>;
    /**
     * 查询退款-直连商户
     */
    queryRefund(data: {
        out_refund_no: string;
    }): Promise<RefundResult>;
    /**
     * 查询退款-服务商
     */
    queryRefundOnProvider(data: {
        out_refund_no: string;
        sub_mchid: string;
    }): Promise<RefundResult>;
    protected _applyTradeBill(data: any): Promise<BillResult>;
    /**
     * 申请交易账单-直连商户
     */
    applyTradeBill(data: Omit<TradeBillParams, 'sub_mchid'>): Promise<BillResult>;
    /**
     * 申请交易账单-服务商
     */
    applyTradeBillOnProvider(data: TradeBillParams): Promise<BillResult>;
    protected _applyFundFlowBill(data: any): Promise<BillResult>;
    /**
     * 申请资金账单-直连商户
     */
    applyFundFlowBill(data: FundflowBillParams): Promise<BillResult>;
    /**
     * 申请资金账单-服务商
     */
    applyFundFlowBillOnProvider(data: FundflowBillParams): Promise<BillResult>;
    /**
     * 申请单个子商户资金账单 仅限服务商
     */
    applySubMerchantFundFlowBill(data: SubMerchantFundflowBillParams): Promise<SubMerchantFundflowBillResult>;
    /**
     * 下载账单(通用)
     */
    downloadBill(download_url: string): Promise<ArrayBuffer>;
}

declare class AppPay extends BasePay {
    constructor(base: WechatPayV3Base);
    private _exOrder;
    /**
     * App支付下单 直连
     */
    order(params: AppOrder_Business): Promise<{
        prepay_id: string;
    }>;
    /**
     * App支付下单 服务商
     */
    orderOnProvider(data: AppOrder_Provider): Promise<{
        prepay_id: string;
    }>;
    /**
     * 获取App调起支付参数
     * @param params
     * @returns
     */
    getPayParams(params: AppReqPaymentParams): {
        appId: string;
        partnerId: string;
        prepayId: string;
        package: string;
        nonceStr: string;
        timeStamp: string;
        sign: string;
    };
}

declare class JSPay extends BasePay {
    order(data: JSAPIOder_Business): Promise<{
        prepay_id: string;
    }>;
    orderOnProvider(data: JSAPIOder_Provider): Promise<{
        prepay_id: string;
    }>;
    /**
     * 获取调起支付参数
     * @param params
     * @returns
     */
    getPayParams(params: ReqPaymentParams): {
        appId: string;
        timeStamp: string;
        nonceStr: string;
        package: string;
        signType: string;
        paySign: string;
    };
}

declare class MiniProgramPay extends BasePay {
    order(data: JSAPIOder_Business): Promise<{
        prepay_id: string;
    }>;
    orderOnProvider(data: JSAPIOder_Provider): Promise<{
        prepay_id: string;
    }>;
    /**
     * 获取调起支付参数
     * @param params
     * @returns
     */
    getPayParams(params: ReqPaymentParams): {
        timeStamp: string;
        nonceStr: string;
        package: string;
        signType: string;
        paySign: string;
    };
}

declare class NativePay extends BasePay {
    constructor(base: WechatPayV3Base);
    private _exOrder;
    /**
     * Native支付下单 直连
     */
    order(params: NativeOrder_Business): Promise<{
        code_url: string;
    }>;
    /**
     * Native支付下单 服务商
     */
    orderOnProvider(data: NativeOrder_Provider): Promise<{
        code_url: string;
    }>;
}

declare class H5Pay extends BasePay {
    constructor(base: WechatPayV3Base);
    private _exOrder;
    /**
     * H5支付下单 直连
     */
    order(params: H5Order_Business): Promise<{
        h5_url: string;
    }>;
    /**
     * H5支付下单 服务商
     */
    orderOnProvider(data: H5Order_Provider): Promise<{
        h5_url: string;
    }>;
}

/**
 * 排除域名中Origin 例如:http://www.a.com/v3/2?a=2 结果为/v3/2?a=2
 * @param url
 * @returns
 */
declare function urlExclueOrigin(url: string): string;
/**
 * 返回当前时间戳
 * @returns
 */
declare function unixTimeStamp(): string;
/**
 * 随机字符串
 * @param length
 * @returns
 */
declare function randomStr(length?: number): string;
/**
 * 路径取文件名
 * @param path
 * @description 适应于windows和linux
 */
declare function path2FileName(path: string): string;
/**
 * 文件摘要
 * @param buffer
 * @description 对文件的二进制内容进行sha256计算得到的值
 */
declare function fileSha256(buffer: Buffer): string;
/**
 * 获取证书序列号
 * @param buf
 * @returns
 */
declare function getCertificateSerialNo(buf: Buffer): string;
/**
 * 获取证书公钥
 */
declare function getCertificatePublicKey(certString: string): KeyObject;
/**
 * 敏感信息加密
 * @param data 待加密数据
 */
declare function encrypt(data: string, key: KeyObject): string;
/**
 * 构造签名信息
 * @param mchid 商户号
 * @param serial_no 商户证书序列号
 * @param nonce_str 随机字符串
 * @param timestamp 时间戳
 * @param signature 签名(buildMessage生成)
 */
declare function getToken(mchid: string, serial_no: string, nonce_str: string, timestamp: string, signature: string): string;
declare function decryptToString_AES(options: {
    ciphertext: string;
    key: string;
    nonce: string;
    associated_data: string;
}): string;
declare function getPublicKey(certString: string): KeyObject;
declare function isUrl(url: string): boolean;
/**
 * 获取系统临时目录
 * @returns
 */
declare function getSysTmpDir(): string;
/**
 * 获取对象路径值
 * @example
 * const obj = {a: {b: {c: 1}},aa:{bb:{cc:{dd:2}}}}}}};
 * getPathValue(obj, 'a.b.c') // 1
 * getPathValue(obj, 'a.b.d') // undefined
 * getPathValue(obj, 'aa.bb.cc.dd') // 2
 */
declare function getPathValue<T>(obj: Record<string, any>, path: string): T;
/**
 * 设置对象路径值
 * @description
 * 1. 如果路径不存在则静默跳过, onSetFail() 会被调用
 * 2. 如果路径存在则设置值
 */
declare function setPathValue(obj: Record<string, any>, path: string, value: any, options?: {
    onSetFail?: (failPath: string) => void;
}): Record<string, any>;
/**
 * 通过标志位和对象替换字符串
 * @description 例如: ('http://www.baidu.com/{name}/{age}', {name: '张三', age: 18}) => http://www.baidu.com/张三/18
 * @param str
 * @param params 参数对象
 * @param beforeToken 默认为 {
 * @param afterToken 默认为 }
 * @returns
 */
declare function replaceTagText<T extends string>(str: T, params: Record<GetUrlParams<T>, string>, beforeToken?: string, afterToken?: string): string;
type GetUrlParams<T extends string, L extends string = '{', R extends string = '}'> = T extends `${infer _}${L}${infer P}${R}${infer R1}` ? P | GetUrlParams<R1, L, R> : never;

export { AppInfo, AppOrder_Business, AppOrder_Provider, AppPay, AppReqPaymentParams, Applyment, ApplymentState, BankAccountType, BaseOrderParams, BasePay, BaseQueryOrderResult, BaseQueryOrderWithOutTradeNo, BaseQueryOrderWithTid, BillResult, BizStoreInfo, BusinessPayerToken, BusinessToken, Certificate, CertificateType, Certificates, ContactIdType, ContactType, ContainerOptions, DecryptCertificates, EncryptCertificate, FinanceType, FundflowBillParams, GetCertificatesResult, GetUrlParams, GoodsDetail, H5Order_Business, H5Order_Provider, H5Pay, IdCardInfo, IdDocInfo, IdDocType, IdHolderType, JSAPIOder_Business, JSAPIOder_Provider, JSAPI_QueryOrder_outTradeNo_Business, JSAPI_QueryOrder_outTradeNo_Provider, JSAPI_QueryOrder_tid_Business, JSAPI_QueryOrder_tid_Provider, JSPay, MiniProgramInfo, MiniProgramPay, ModifySettlementAccountBody, MpInfo, NativeOrder_Business, NativeOrder_Provider, NativePay, OrderParamsAmount, OrderParamsDetail, OrderParamsDetailGoodsDetail, OrderParamsSceneInfo, OrderParamsSceneInfoStoreInfo, OrderParamsSettleInfo, OrderResult, ProviderPayerToken, ProviderToken, QueryApplymentStateResult, QueryOrderAmount, QueryOrderGoodsDetail, QueryOrderPromotionDetail, QueryOrderResult_Business, QueryOrderResult_Provider, QuerySettlementAccountResult, RefundAmount, RefundResult, Refund_Business, Refund_Provider, ReqPaymentParams, ResultFundsAccountEnum, ResultPromotionDetail, ResultRefundAmount, ResultRefundChannelEnum, ResultRefundStatusEnum, SalesScenesType, SubMerchantFundflowBillParams, SubMerchantFundflowBillResult, SubToken, SubjectType, SubmitApplicationAdditionInfo, SubmitApplicationBankAccountInfo, SubmitApplicationBody, SubmitApplicationBusinessInfo, SubmitApplicationBusinessLicenseInfo, SubmitApplicationCertificateInfo, SubmitApplicationContactInfo, SubmitApplicationFinanceInstitutionInfo, SubmitApplicationIdentityInfo, SubmitApplicationSettlementInfo, SubmitApplicationSubjectInfo, SubmitApplicationUboInfo, SubmitApplicationsResult, TradeBillParams, TradeStateEnum, TradeTypeEnum, UploadImageResult, WebInfo, WechatBaseEventOPtions, WechatBaseOptions, WechatPayV3Base, WeworkInfo, apiContainer, decryptToString_AES, encrypt, fileSha256, getCertificatePublicKey, getCertificateSerialNo, getInstances, getPathValue, getPublicKey, getSysTmpDir, getToken, isUrl, path2FileName, randomStr, replaceTagText, setPathValue, unixTimeStamp, urlExclueOrigin };
