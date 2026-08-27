# TODO: Refactor this later
# FIXME: This is temporary


def risky_function(user):

    if user:

        if user.is_admin:

            if user.is_active:
                print("Admin")

            else:
                print("Inactive admin")

        elif user.is_guest:

            if user.is_verified:
                print("Verified guest")

            else:
                print("Unverified guest")

    else:

        print("No user")