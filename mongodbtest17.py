from flask import Flask, request, json
from flask_restful import Resource, Api
from mongoengine import *
import time, random
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message


app = Flask(__name__)
api = Api(app)
connect('qingqing01')
app.config.update(
	MAIL_SERVER='smtp.qq.com',
	MAIL_PORT='465',
	MAIL_USE_SSL=True,
	MAIL_USERNAME='276309888@qq.com',
    MAIL_DEFAULT_SENDER = '276309888@qq.com',
	MAIL_PASSWORD='flvjttrlvnesbgjg'
	)
mail = Mail(app)


# 初始化建表
class userRegister(Document):
    loginAccount = StringField(required = True, unique=True, max_length=50)
    psdHsCode = StringField(max_length = 255, unique=True, required = True)
    registerTime = StringField(max_length = 50, required = True)
    mailVerificateCode = StringField(max_length = 255, required = True)
    meta = {'allow_inheritance': True}


class userLogin(Document):
    loginAccount = StringField(required = True, unique=True, max_length=255)
    quid = StringField(max_length = 255, unique=True, required = True)
    meta = {'allow_inheritance': True}


class userList(Document):
    quid = StringField(required = True, unique=True, max_length=255)
    userName = StringField(max_length=255, required=True)
    sex = StringField(max_length=100)
    location = StringField(max_length=255)
    age = StringField(max_length=100)
    qqNum = StringField(max_length=100)
    wechatNum = StringField(max_length=100)
    phoneNum = StringField(max_length=100)
    qAuthority = StringField(max_length=100)
    ifVip = StringField(max_length=100)
    vipLevel = StringField(max_length=100)
    userScore = StringField(max_length=100)
    lastLoginTime = StringField(max_length=100)
    imgUrl =  StringField(max_length=255)
    userDetail = StringField(max_length=255)
    userHobby = StringField(max_length=255)
    userJob = StringField(max_length=100)
    userRole = StringField(max_length=100)
    userEmail = StringField(max_length=100)
    meta = {'allow_inheritance': True}

# 设置token失效密钥，后续放到配置文件中
invalidKey = 'secretKey'
# 设置注册成功后token失效时间，后续放到配置文件中
invalidtimeNew = 3600
# 设置登录成功后token失效时间，后续放到配置文件中
invalidtime = 3600

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    try:
        if request.method == 'POST':
            # 新增一条Register数据*************************************************************************************
            loginaccount = request.headers.get("userName",type=str)
            psdhscode = generate_password_hash(request.headers.get("psd",type=str))
            # 时间存储，时间字符串/时间戳字符串
            # registertime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            registertime = str(time.time()) 
            addUserRegister = userRegister(loginAccount=loginaccount, psdHsCode=psdhscode, registerTime=registertime).save()

            # 新增一条Login数据****************************************************************************************
            # 生成quid--------------------------------------------------------------------------------------------
            # Q+时间部分
            timeString = "Q" + time.strftime("%Y%m%d", time.localtime())
            # 生成最新的右面6位
            todayRightNew6 = str(len(userLogin.objects(quid__istartswith=timeString).only('quid'))+1).rjust(6,'0')
            # 生成随机数
            random1 = random.sample('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',4)
            randomNew = ''.join(random1)
            # 生成今天最新的QUID
            newTodayQuid = timeString + todayRightNew6 + randomNew
            addUserLogin = userLogin(loginAccount=loginaccount, quid=newTodayQuid).save()

            # 新增一条Register数据*************************************************************************************
            addUserList = userList(
                quid=newTodayQuid,
                userName=loginaccount,
                sex='',
                location='',
                age='',
                qqNum='',
                wechatNum='',
                phoneNum='',
                qAuthority='',
                ifVip='',
                vipLevel='',
                userScore='',
                lastLoginTime='',
                imgUrl='',
                userDetail='',
                userHobby='',
                userJob='',
                userRole='',
                userEmail='').save()

            # 注册成功生成的token，建议设置失效时间--------------------------------------------------------------------
            # 生成token前的序列化，并预留失效时间（单位s）
            serializer = Serializer(invalidKey, invalidtimeNew)
            # 要加入token的信息
            addTokenInfoLoginAccount = {'userName':loginaccount}
            # 生成新token
            tokenNew = serializer.dumps(addTokenInfoLoginAccount).decode('utf-8')

            return(tokenNew)
            return("恭喜亲~注册成功~")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("亲~该用户名已存在~")


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    try:
        if request.method == 'POST':
            # 获取前端传来的账号、密码
            username = request.headers.get("userName",type=str)
            psd = request.headers.get("psd",type=str)
            # 获取数据库中对应用户名的HSCODE
            try:
                getHsCode = userRegister.objects(Q(loginAccount=username))[0].psdHsCode
            except IndexError:
                return("账号不存在~")
            # 验证密码
            if check_password_hash(getHsCode, psd):
                # 验证通过后，生成token
                serializer = Serializer(invalidKey, invalidtime)
                userToken = serializer.dumps({"userName":username}).decode('utf-8')
                return(userToken)
            else:
                # 根据前端需求可调整返回内容
                return("密码错误")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")


@app.route('/modify_password', methods=['GET', 'POST'])
def modify_password():
    try:
        if request.method == 'POST':
            # 获取前端传来的账号及旧、新密码
            username = request.headers.get("userName",type=str)
            oldPassword = request.headers.get("oldPsd",type=str)
            newPsdHsCode = generate_password_hash(request.headers.get("newPsd",type=str))
            # 获取数据库中对应用户名的HSCODE
            try:
                getHsCode = userRegister.objects(Q(loginAccount=username))[0].psdHsCode
            except IndexError:
                return("账号不存在~")
            # 验证密码
            if check_password_hash(getHsCode, oldPassword):
                # 验证通过后，更新新密码
                userRegister.objects(loginAccount=username).update(psdHsCode=newPsdHsCode)
                return("密码修改成功")
            else:
                # 根据前端需求可调整返回内容
                return("旧密码错误")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")
 

@app.route('/get_mailVerificateCode', methods=['GET', 'POST'])
def get_mailVerificateCode():
    try:
        if request.method == 'POST':
            # 获取前端传来的账号
            username = request.headers.get("userName",type=str)
            try:
                getHsCode = userRegister.objects(Q(loginAccount=username))[0].psdHsCode
                # 判断当前用户可用的密保方式
                if userList.objects(Q(userName=username))[0]['userEmail'] == '':
                    # ***********如果没有Email，就后续返回个链接让用户设置一个邮箱
                    # 后续调整为跳转绑定邮箱（或其他方式）
                    return("该用户没有密保邮箱~")
                else:
                    recipienter = userList.objects(Q(userName=username))[0]['userEmail']
                    mailverificationcode = ''.join(random.sample('0123456789',6))
                    newMvcodeHsCode = generate_password_hash(mailverificationcode)
                    userRegister.objects(loginAccount=username).update(mailVerificateCode=newMvcodeHsCode)
                    msg = Message(subject="青青账号安全验证", recipients=[recipienter])
                    msg.body='敬爱的用户：'+username+'您好！我们已收到您的密码重置申请，请妥善保管，切勿泄露验证码：'+mailverificationcode
                    mail.send(msg)
                    return("验证码已发送，请注意查收~")
            except IndexError:
                return("账号不存在~")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")


@app.route('/get_psdProtectWay', methods=['GET', 'POST'])
def get_psdProtectWay():
    try:
        if request.method == 'POST':
            # 获取前端传来的账号
            username = request.headers.get("userName",type=str)
            try:
                getHsCode = userRegister.objects(Q(loginAccount=username))[0].psdHsCode
                # 获取当前用户可用的密保方式
                psdProtectWayList = ['phoneNum','userEmail']
                psdProtectWay = {}
                for i in psdProtectWayList:
                    if userList.objects(Q(userName=username))[0][i] == '':
                        pass
                    else:
                        # 为保安全，需替换字符串中间几位
                        psdProtectWayValue = userList.objects(Q(userName=username))[0][i]
                        # 计算获取的字符串长度一半取整
                        psdProtectWayValueLen = int(len(psdProtectWayValue)/2)
                        # 替换字符串中间的一版为*
                        psdProtectWay[i] = psdProtectWayValue.replace(psdProtectWayValue[int(psdProtectWayValueLen-psdProtectWayValueLen/2):int(psdProtectWayValueLen+psdProtectWayValueLen/2)],'*'*psdProtectWayValueLen)
                if psdProtectWay != {}:
                    return(json.dumps(psdProtectWay))
                else:
                    # 后续调整为跳转绑定邮箱（或其他方式）
                    return("该用户没有密保方式~")
            except IndexError:
                return("账号不存在~")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    try:
        if request.method == 'POST':
            # 获取前端传来的旧、新密码
            username = request.headers.get("userName",type=str)
            newPassword = request.headers.get("newPsd",type=str)
            yzm = request.headers.get("yzm",type=str)
            # 获取数据库中对应用户名的HSCODE
            try:
                getmailVerificateCode = userRegister.objects(Q(loginAccount=username))[0].mailVerificateCode
            except IndexError:
                return("账号不存在~")
            # 核对验证码是否正确
            if check_password_hash(getmailVerificateCode, yzm):
                # 验证通过后，更新新密码
                newResetPsdHsCode = generate_password_hash(request.headers.get("newPsd",type=str))
                userRegister.objects(loginAccount=username).update(psdHsCode=newResetPsdHsCode)
                # 验证通过后，更新新验证码
                mailverificationcode = ''.join(random.sample('0123456789',6))
                newMvcodeHsCode = generate_password_hash(mailverificationcode)
                userRegister.objects(loginAccount=username).update(mailVerificateCode=newMvcodeHsCode)
                return("密码重置成功")
            else:
                # 根据前端需求可调整返回内容
                return("验证码错误")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")


@app.route('/set_mailaccount', methods=['GET', 'POST'])
def set_mailaccount():
    try:
        if request.method == 'POST':
            # 获取前端传来的旧、新密码
            username = request.headers.get("userName",type=str)
            mailaccount = request.headers.get("email",type=str)
            # 获取数据库中对应用户名的HSCODE
            try:
                getUserMail = userList.objects(Q(userName=username))[0].userEmail
            except IndexError:
                return("账号不存在~")
            # 判断用户是否有邮箱
            if getUserMail == '':
                # 判断传来的邮箱是否为空
                if mailaccount:
                    # 验证通过后，设置邮箱
                    userList.objects(userName=username).update(userEmail=mailaccount)
                    return("密保邮箱设置成功")
                else:
                    return("没有传邮箱号码~")
            else:
                # 根据前端需求可调整返回内容
                return("您已有密保邮箱~可登陆验证后进行修改哦~")
        else:
            return("亲~请求方式一定要'POST'哦~")
    except NotUniqueError:
        return("其他错误？")

 
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5003, debug=True)
