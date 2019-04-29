# Usom IP Blacklist

Ulusal Olaylara Müdahale Merkezi (Kısaca USOM), resmi internet sitesinde, “Zararlı Bağlantılar” diye bir servis sunmaktadır. 

**https://www.usom.gov.tr/url-list.txt**

USOM, kendisine yapılan ihbarlar ve kendi çalışmalarıyla belirlediği zararlı içerik paylaşan, domain, url ve ip adreslerinin listesini XML ve TXT olarak yayınlıyor.

Bilindiği gibi, Firewall ve IPS gibi güvenlik cihazlarına text tabanlı ip reputation adresleri eklenerek, bu iplerden gelen veya bu iplere doğru yapılan isteklerin güvenlik cihazlarından direk bloklanması sağlanabilmektedir.

USOM listesi, ip, domain ve url linkler içermesi sebebiyle, direk olarak bu amaçla kullanılamamaktadır.

# Usom IP Blacklist Özellikleri:
– Liste oluşturulduktan sonra tekrarlayan ipler çıkarıldı ve ipler sıraya konuldu.
– 0.0.0.0, 127.0.0.1, 8.8.8.8, 8.8.4.4 ip adreslerini çözen kayıtlar çıkartıldı, bu domainler geçersiz domain olarak belirlendi.
– Bazı domainler için ip kaydı olmadığından bu domainleri log dosyasından görebilirsiniz.


# Uygulama iki adet çıktı üretmektedir: 
1. **usom-ip-list.txt:**  USOM IP listesi
2. **usom-ip-list-output.txt:** Listeyi kullanacak kullanıcılarımızın, hangi domain ve url’in, hangi ipye karşılık geldiğini de rahatça görebilmesi açısından listenin log dosyası

**Hilmi Esen**