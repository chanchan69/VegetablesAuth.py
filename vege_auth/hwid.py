from subprocess import check_output


def hwid() -> str:
    return check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
