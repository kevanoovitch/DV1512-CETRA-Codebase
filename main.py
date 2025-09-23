from backend.api import preform_secure_annex_scan, print_secure_annex_scan


def main():

    monkey_type_id = "ekkfdhandgcjdkdlfppjkedoaiiccdaa"
    preform_secure_annex_scan(monkey_type_id)

    print_secure_annex_scan(monkey_type_id)

if __name__ == "__main__":
    main()
