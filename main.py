from backend.api import preform_secure_annex_scan, print_secure_annex_scan


def main():

    id = "deljjimclpnhngmikaiiodgggdniaooh" # A extension ID
      
    
    preform_secure_annex_scan(id)

    print_secure_annex_scan(id)

if __name__ == "__main__":
    main()
