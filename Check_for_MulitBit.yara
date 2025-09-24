rule MultiBit_Bitcoin_Blockchain_File {

        meta:
                author = "AR Wiley"
                description = "Check for MulitBit Lightweight Bitcoin Wallet"
                date = "9/23/25"
                sha256 = "04f7f89d5eb5b284ef2128d8088f111afaaeff0aad2b47e7e94916c82041a91f"
                md5 = "1a4b7db4ddf0fcaddacea01523be7128"

        strings:
                $s = { 53 50 56 42 }
                $s1 = "multibit.blockchain"
                $s2 = ".aes.json"
                $s3 = ".zip.aes"
                $s4 = "%APPDATA%\\MultiBitHD"
                $s5 = "mbhd.wallet.aes"
                $s6 = ".multibit"
                $s7 = "~/Library/Application Support/MultiBit"

        condition:
                any of them

}
