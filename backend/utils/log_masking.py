"""
日志掩码工具模块
用于在日志中隐藏敏感信息
"""

def mask_sensitive_data(value: str, data_type: str = "default") -> str:
    """
    掩码敏感数据

    Args:
        value: 要掩码的值
        data_type: 数据类型（password, token, email, default）

    Returns:
        掩码后的值
    """
    if not value:
        return "***"

    if data_type == "password":
        # 密码：只显示前2位和后2位
        if len(value) <= 4:
            return "***"
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

    elif data_type == "token":
        # Token：只显示前8位和后4位
        if len(value) <= 12:
            return "***"
        return f"{value[:8]}...{value[-4:]}"

    elif data_type == "email":
        # Email：隐藏中间部分
        at_pos = value.find('@')
        if at_pos <= 0:
            return "***@***.***"
        username = value[:at_pos]
        domain = value[at_pos + 1:]
        if len(username) <= 2:
            masked_username = "*" * len(username)
        else:
            masked_username = f"{username[0]}{'*' * (len(username) - 2)}{username[-1]}"
        return f"{masked_username}@{domain}"

    elif data_type == "username":
        # 用户名：显示部分信息
        if len(value) <= 3:
            return "***"
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"

    else:
        # 默认：显示部分信息
        if len(value) <= 6:
            return "***"
        return f"{value[:3]}...{value[-3:]}"


def log_with_masking(logger, message: str, sensitive_fields: dict = None):
    """
    使用掩码记录日志

    Args:
        logger: logger 对象
        message: 日志消息
        sensitive_fields: 敏感字段字典 {字段名: (值, 类型)}
    """
    if sensitive_fields:
        masked_message = message
        for field_name, (value, data_type) in sensitive_fields.items():
            masked_value = mask_sensitive_data(value, data_type)
            masked_message = masked_message.replace(str(value), masked_value, 1)
        logger.info(masked_message)
    else:
        logger.info(message)
