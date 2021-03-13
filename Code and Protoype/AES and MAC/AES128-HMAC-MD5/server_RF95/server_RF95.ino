// import library for MAC
#include <string.h>
#include <Crypto.h>
#include <AESLib.h>
#include <MD5.h>

#define HASH_SIZE 16

// import library for lora
#include <SPI.h>
#include <RH_RF95.h>

#define RFM95_CS 10
#define RFM95_RST 7
#define RFM95_INT 2

// Change frequency, must match RX's freq!
#define RF95_FREQ 868.1

// Singleton instance of the radio driver
RH_RF95 rf95(RFM95_CS, RFM95_INT);

// Initiate key
const char *key = "putriawloramac"; 

// Initiate MD5
MD5 md5;

// Initiate AES128
uint8_t aes_key[16]  ={0x50, 0x55, 0x54,0x52, 0x49, 0x41, 0x57, 0x4C, 0x4F, 0x52, 0x41, 0x45, 0x53, 0x31, 0x32, 0x38};

// Initiate variable for timestamping
unsigned long start;
unsigned long elapsed;

void setup() 
{   
  Serial.begin(9600);
  while (!Serial) ; // Wait for serial port to be available

  // call setup RF Lora function
  setupRF();

  // Encrypt setting
  crypto_feed_watchdog();  
 
}

void loop()
{
  if (rf95.available())
  {
    // Should be a message for us now   
    uint8_t buf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t len = sizeof(buf);
    
    // Start Timestamping to wait for reply
    start = micros();
    
    if (rf95.recv(buf, &len))
    {
      Serial.println("==================================");
      Serial.println("got request: ");
      
      // End of Receiving data Timestamping
      elapsed = micros() - start;
      Serial.print("[Response Receiving Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();
      
      // Start Timestampping for decryptio process
      start = micros();
      
      size_t mslen = len - (HASH_SIZE*2);
      uint8_t rmsg[mslen];
      uint8_t rmac[HASH_SIZE*2];

      // Decrypt Message
      aes128_dec_single(aes_key, buf);
      Serial.print("DECRYPTED MESSAGE : ");
      printData(buf, len);
      Serial.println("");

      // End of Decrypt timestamping
      elapsed = micros() - start;
      Serial.print("[Decryption Process Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();
      
      // Start Timestampping for mac verify process
      start = micros();
      
      // Parse message
      parseRecvData(buf, len, mslen, rmsg, rmac);
      Serial.print("MESSAGE           : ");
      printData(rmsg, mslen );
      Serial.println();
      Serial.print("HMAC-MD5          : ");
      printMD5((char*)rmac, (HASH_SIZE*2));

      // Verify MAC
      char *md5s = hashMD5.hmac_md5((void*)rmsg, mslen, (void*)key, strlen(key));
      macVerify(strupr(md5s),(char*)rmac );
      
      memset(rmac, 0, sizeof(rmac));
      memset(rmsg, 0, sizeof(rmsg));

      // End of MAC Verify timestamping
      elapsed = micros() - start;
      Serial.print("[MAC Verify Process Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();
      Serial.println("==================================");

      // Send a reply
      Serial.println("Sent a reply");
      
      // Start timestamping for mac process
      start = micros();
      const char *pesan = "Yes I'am";
      
      // MAC Process 
      char *md5str = hashMD5.hmac_md5((void*)pesan, strlen(pesan), (void*)key, strlen(key));
      Serial.print("HMAC MD5            : ");
      char *md5up = strupr(md5str);
      printMD5(md5up, HASH_SIZE*2);

      // End of MAC Generation Timestamping 
      elapsed = micros() - start;
      Serial.print("[MAC Generation Process Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();

      // Start timestamping for Encryption process
      start = micros();
      
      // Concate message and MAC
      int len = strlen(pesan)+(HASH_SIZE*2);
      uint8_t data[len];
      concMessage((uint8_t*)pesan, (uint8_t*)md5str, data, strlen(pesan), (HASH_SIZE*2));
      Serial.print("MESSAGE + HMAC-MD5  : ");
      printData(data, strlen(pesan));
      printMD5(md5str, HASH_SIZE*2);
     
      // Encrypt
      aes128_enc_single(aes_key, data);
      Serial.print("ENCRYPTED MESSAGE   : ");
      printData(data, 16);
      Serial.println();
      
      // Send Data to Client
      rf95.send((const uint8_t*)(&data), sizeof(data));
      rf95.waitPacketSent();

      memset(data, 0, sizeof(data));

      // End of Encryption processing Timestamping 
      elapsed = micros() - start;
      Serial.print("[Encryption Process Time in ms] -> ");
      Serial.print(elapsed / 1000.0);
      Serial.println();
      Serial.println("==================================");
    }
    else
    {
      Serial.println("recv failed");
    }
  }
}

// Inisiai RF
void setupRF() {
  pinMode(RFM95_RST, OUTPUT);
  digitalWrite(RFM95_RST, HIGH);

  // manual reset
  digitalWrite(RFM95_RST, LOW);
  delay(10);
  digitalWrite(RFM95_RST, HIGH);
  delay(10);

  while (!rf95.init()) {
    Serial.println("LoRa radio init failed");
    while (1);
  }
  Serial.print("LoRa As RECEIVER OK: ");
  Serial.println(RF95_FREQ);

  // Defaults after init are 434.0MHz, modulation GFSK_Rb250Fd250, +13dbM
  if (!rf95.setFrequency(RF95_FREQ)) {
    Serial.println("setFrequency failed");
    while (1);
  }

  // Defaults after init are 434.0MHz, 13dBm, Bw = 125 kHz, Cr = 4/5, Sf = 128chips/symbol, CRC on
  // The default transmitter power is 13dBm, using PA_BOOST.
  // If you are using RFM95/96/97/98 modules which uses the PA_BOOST transmitter pin, then
  // you can set transmitter powers from 5 to 23 dBm:
  rf95.setTxPower(23, false);
}

// Verifiy MAC
void macVerify(char *md5s, char *md5r)
{
    if (!memcmp(md5s, md5r, HASH_SIZE))
        Serial.println("HMAC VERIFY STATUS : MATCH");
    else
        Serial.println("HMAC VERIFY STATUS : UNMATCH");
}

// Print Decrypted Data
void printData(uint8_t value[], size_t len){
  for (uint8_t i = 0; i < len; i++) {
    Serial.print(value[i], HEX);
    Serial.print(" ");
  }
}

// Print MD5
void printMD5(char value[], size_t len){
  int i = 0;
  while (i < len){
  
    Serial.print(value[i]);
    Serial.print(value[i+1]);
    Serial.print(" ");
    i = i + 2;
  }
  Serial.println();
}

// Parse data from sender
void parseRecvData(uint8_t value[], uint8_t len, size_t mslen, uint8_t msg[], uint8_t mac[]){
  int j = 0;
  for (uint8_t i = 0; i < len; i++) {
    if(i < mslen){
      msg[i] = value[i];
    }else{
      mac[j] = value[i];
      j++;
    }
  }
}

// Concate Message
void concMessage(uint8_t msg[], uint8_t key[], uint8_t cocmsg[], size_t mlen, size_t klen){
  uint8_t j = 0;
  for (uint8_t i = 0; i < mlen+klen; i++) {
    if (i < mlen) {
      cocmsg[i] = msg[i];
    }else{
      cocmsg[i] = key[j];
      j++;
    }
  }
}
