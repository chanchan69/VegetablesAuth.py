from vege_auth import AuthClient, AuthError


def login():
    c = AuthClient("your_aid", "your_api_key", "your_client_secret", "your_rsa_private_key")  # rsa key is only needed if you need to decrypt the variables

    try:
        response = c.authenticate("chanchan", "chanchan's password")

        print(f"Successfully logged in, your license type is: {response.license_type}")
    except AuthError as ex:
        print(f"An error occurred: {ex}")


def register():
    c = AuthClient("your_aid", "your_api_key", "your_client_secret", None)

    response = c.register("chanchan", "chanchan's password", "chanchan@sirchanchan.dev",
                          "LICENSE-6672-41b8-ba50-5f41114b1774")

    print(f"Auth message: {response}")


def reset():
    c = AuthClient("your_aid", "your_api_key", "your_client_secret", None)

    response = c.reset("chanchan", "chanchan's password", "RESET-6672-41b8-ba50-5f41114b1774")

    print(f"Auth message: {response}")
