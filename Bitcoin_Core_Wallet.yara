rule Bitcoin_Core_Wallet {

        meta:
                author = "AR Wiley"
                description = "Check for Bitcoin Core Wallet"
                date = "2025-10-05"

        strings:
                $s = { 	00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00 }
                $s1 = "~/Library/Application Support/Bitcoin/"
                $s2 = "~/.bitcoin/"
                $s3 = "\\AppData\\Roaming\\Bitcoin\\" nocase
                $s4 = "%APPDATA%\\Bitcoin\\" nocase
                $s5 = "wallet.dat"
                $s6 = "bitcoin.conf"
                $s7 = "blkNNNNN.dat"
				$s8 = "wallet.dat-journal"
				$s9 = ".walletlock"

        condition:
                2 of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9) or $s


}


