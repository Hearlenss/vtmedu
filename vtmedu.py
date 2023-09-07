import requests
import os

# Terminal ekranını temizle
os.system("clear") #eğer windows kullanıyorsanız burayı os.system("cls") şeklinde güncellemelisiniz aksi halde temizlemez linux ve macos bu şekilde kalabilir.
print("""
         _________ _______  _______  ______           
|\     /|\__   __/(       )(  ____ \(  __  \ |\     /|
| )   ( |   ) (   | () () || (    \/| (  \  )| )   ( |
| |   | |   | |   | || || || (__    | |   ) || |   | |
( (   ) )   | |   | |(_)| ||  __)   | |   | || |   | |
 \ \_/ /    | |   | |   | || (      | |   ) || |   | |
  \   /     | |   | )   ( || (____/\| (__/  )| (___) |
   \_/      )_(   |/     \|(_______/(______/ (_______)
-------------https://github.com/Hearlenss-------------
-----------------VirusTotal Paneli 1.0----------------
---------'REDLİNE--------------------'MEDUSA----------
""")

API_KEY = 'api key buraya'

def dosya_tara(dosya):
    # dosya yolunu kontrol eder
    if not os.path.exists(dosya):
        print(f"{dosya} adlı dosya bulunamadı. Lütfen dosya yolunu kontrol edin.")
        return None
    #api endpointler
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    if dosya.startswith("http") or dosya.startswith("www"):
        url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        params['url'] = dosya
        dosyalar = None
    else:
        dosyalar = {'file': (dosya, open(dosya, 'rb'))}
    yanıt = requests.post(url, files=dosyalar, params=params)
    sonuç = yanıt.json()
    return sonuç

# Hash değerini tarama 
def hash_değerini_tara(hash_değeri):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': hash_değeri}    
    yanıt = requests.get(url, params=params)
    sonuç = yanıt.json()
    return sonuç

def sonucunu_yazdır(sonuç):
    if sonuç.get('response_code', 0) == 1:
        print("Sonuçlar:")
        taramalar = sonuç.get('scans', {})
        for antivirus, sonuç in taramalar.items():
            print(f"{antivirus}: {sonuç.get('result', 'N/A')}")
    else:
        print("Sonuç henüz hazırlanıyor. Biraz sonra lütfen tekrar deneyin.")

# yazılan hash değerleri ve scan id
def dosya_sonucunu_yazdır(sonuç):
    print("\nHash Değerleri:")
    print(f"Scan ID: {sonuç.get('scan_id', 'N/A')}")
    print(f"MD5: {sonuç.get('md5', 'N/A')}")
    print(f"SHA-1: {sonuç.get('sha1', 'N/A')}")
    print(f"SHA-256: {sonuç.get('sha256', 'N/A')}")
    print(f"Permalink: {sonuç.get('permalink', 'N/A')}")


if __name__ == '__main__':
    while True:
        print("\nVirüsTotal Paneli")
        print("1. Dosya Taraması")
        print("2. Hash Taraması")
        print("3. Çıkış")
        seçenek = input(">>>")
        
        if seçenek == '1':
            dosya_adı = input("Dosyanın Yolu: ")
            tarama_sonucu = dosya_tara(dosya_adı)
            if tarama_sonucu is not None: 
                tarama_id = tarama_sonucu.get('scan_id', '')
                if tarama_id:
                    print(f"Tarama Sonucu Yükleniyor Scan ID: {tarama_id}")
                    rapor = hash_değerini_tara(tarama_id)
                    sonucunu_yazdır(rapor)
                else:
                    print("Hata, Tekrar Deneyin")
                dosya_tarama_sonucu = dosya_tara(dosya_adı)
                dosya_sonucunu_yazdır(dosya_tarama_sonucu)
        elif seçenek == '2':
            hash_değeri = input("Taramak istediğiniz dosyanın hash'ini girin: ")
            rapor = hash_değerini_tara(hash_değeri)
            sonucunu_yazdır(rapor)
        elif seçenek == '3':
            print("Programdan çıkılıyor.")
            break
        else:
            print("Geçerli bir seçenek seçilmedi.")
