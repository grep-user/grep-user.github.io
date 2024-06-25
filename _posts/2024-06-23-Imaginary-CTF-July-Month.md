---
title: Imaginary CTF July Month Writeup
published: true
---

Imaginary CTF organizes CTF every year, along with it they also create monthly challenges for users to play, featuring a leaderboard for each month.

Whener I have some time, I use to play this challenges. So in this month they released few [challenges](https://imaginaryctf.org/ArchivedChallenges/54)

So this time I solved few challenges, so here are some solutions I come up with during challenge.

### Functional Programming [Reversing]

This challenge contains output from the binary and C++ source file. So our goal in this challenge is to reverse the flag. Looking through C++ code we can see that the flag variable should have contained the real flag and it goes through some XORs and some binary options to convert the flag and prints it in hex format. 

```C++
char globalvar=0;

unsigned char flag[]="REDACTED";

unsigned char eor(unsigned char a)
{
	return a^0x007;
}

unsigned char inc(unsigned char a)
{
	flag[globalvar]=a;
	globalvar++;
	return flag[globalvar];
}

unsigned char rtr(unsigned char a)
{
	return (a >> 1) | (a << (8-1) );
}


int main()
{
	
	inc(rtr(inc(eor(eor(inc(rtr(rtr(rtr(inc(eor(rtr(eor(inc(rtr(rtr(inc(eor(rtr(rtr(inc(eor(inc(rtr(rtr(rtr(inc(eor(eor(eor(inc(rtr(inc(eor(inc(rtr(rtr(rtr(inc(eor(eor(eor(rtr(inc(rtr(rtr(rtr(inc(eor(rtr(rtr(inc(eor(eor(eor(inc(rtr(rtr(rtr(eor(inc(eor(rtr(eor(rtr(inc(eor(rtr(eor(inc(rtr(inc(rtr(inc(eor(inc(eor(inc(rtr(eor(inc(rtr(inc(eor(inc(rtr(eor(flag[globalvar])))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
	for(int i=0;i<27;i++)printf("%x ",flag[i]);
	printf("\n");
	return 0;
}
```

Inorder to solve this challenge I recreated the program in python. From the code it is clear each `inc` function call saves the encoded output of the char in the array and returns next char in the array to be encoded. 

My first step was to convert the hex to decimal format. 

```python
FLAG = "18 6f 98 19 58 70 b0 9a 2b dc b 6a 4b a6 9c 2c 6c 99 58 2c 36 9f 8c 35 66 64 1a".split(" ")
flag_arr = [(int('0x'+i,16)) for i in FLAG]
```

The next step is to reverse the `eor` and `rtr` function. Since `eor` function just **XORs** the input, we can easily reverse it.

```python
def reor(a):
	return (a^0x007) & 0xFF 
```

In my next step I converted the **rtr** function which returns `OR` of right shift of **input** to `1` and left shif to **input** to `7`.

In order to reverse I created a function which loops through `256` times[since each char is 8 bit long] and brute forced the output for the given input.  

```python
def rrtr(a):
    for x in range(256):  # Possible values for an 8-bit number
        if (((x >> 1) | (x << 7)) & 0xFF) == a:  # Ensuring it fits within 16 bits
            return x
    return None
```

Finally calling reverse functions for each iterations. I have'nt created reverse `inc` function, because I called reverse function for each character separatedly which gets my work done faster than writing its reverse. 

```python
if __name__ == "__main__":
    flag_arr = [(int('0x'+i,16)) for i in FLAG]
    
    print(chr(reor(rrtr(flag_arr[0])))+
    chr(reor(flag_arr[1]))+
    chr(rrtr(flag_arr[2]))+
    chr(reor(rrtr(flag_arr[3])))+
    chr(reor(flag_arr[4]))+
    chr(reor(flag_arr[5]))+
    chr(rrtr(flag_arr[6]))+
    chr(rrtr(flag_arr[7]))+
    chr(reor(rrtr(reor(flag_arr[8]))))+
    chr(rrtr(reor(rrtr(reor(flag_arr[9])))))+
    chr(reor(rrtr(rrtr(rrtr(flag_arr[10])))))+
    chr(reor(reor(reor(flag_arr[11]))))+
    chr(rrtr(rrtr(reor(flag_arr[12]))))+
    chr(rrtr(rrtr(rrtr(flag_arr[13]))))+
    chr(rrtr(reor(reor(reor(flag_arr[14])))))+
    chr(rrtr(rrtr(rrtr(flag_arr[15]))))+
    chr(reor(flag_arr[16]))+
    chr(rrtr(flag_arr[17]))+
    chr(reor(reor(reor(flag_arr[18]))))+
    chr(rrtr(rrtr(rrtr(flag_arr[19]))))+
    chr(reor(flag_arr[20]))+
    chr(rrtr(rrtr(reor(flag_arr[21]))))+
    chr(rrtr(rrtr(flag_arr[22])))+
    chr(reor(rrtr(reor(flag_arr[23]))))+
    chr(rrtr(rrtr(rrtr(flag_arr[24]))))+
    chr(reor(reor(flag_arr[25])))+
    chr(rrtr(flag_arr[26])))
```

Finally running the program prints the **flag**.

```bash
python3 sol.py
7h15_wa5_a_m157ak3_a1b2c3d4
```

### Three Characters [Web]

In this challenge, we are given a golang file which runs a http server which updates password for some time delay(looks like 10 seconds). The password is randomly chosen 32 characters from `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`. The goal of this challenge is to find correct password.

The server has 4 route handler. The `/source` and `/docker` are used to display the source and the dockerfile for the challenge. `/password` route reads password from form parameter, checks if it is equal to the password and returns the flag in response. So the goal of this challenge is to guess the 32 bytes random password which gets updated every 10 seconds.

But there is this one route `/characters` which looks suspicious. The **charactersHandler** will create 3 random integer within passwordLength and returns sha1 hash of characters in those indexes of password. 


```go
package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

//go:embed main.go
var source []byte

//go:embed Dockerfile
var docker []byte

var password string

var passwordLength = 32
var passwordNumber = 0

var hashes = make(map[string]string)
var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var keyPattern = "%d-%d-%d"

var globalVar = 0

type charactersResponse struct {
	Indices []int  `json:"indices"`
	Hash    string `json:"hash"`
	Number  int    `json:"number"`
}

func randStringBytes(n int) string {

	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
		globalVar += 1
	}
	
	return string(b)
}

func updatePassword() {
	password = randStringBytes(passwordLength)
	tempHashes := make(map[string]string)

	for i := 0; i < passwordLength; i++ {
		for j := 0; j < passwordLength; j++ {
			for k := 0; k < passwordLength; k++ {
				key := fmt.Sprintf(keyPattern, i, j, k)
				hash := fmt.Sprintf("%x", sha1.Sum([]byte{password[i], password[j], password[k]}))

				tempHashes[key] = hash
			}
		}
	}

	hashes = tempHashes
	passwordNumber += 1
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func sourceHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(source)
}

func dockerHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(docker)
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Failed to parse request"))
		return
	}

	if r.Form.Get("password") == password {
		fmt.Fprintf(w, "Flag: %s", os.Getenv("FLAG"))
		return
	}

	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Incorrect password"))
}

func charactersHandler(w http.ResponseWriter, r *http.Request) {
	indicies := []int{rand.Intn(passwordLength), rand.Intn(passwordLength), rand.Intn(passwordLength)}
	
	globalVar += 1
	globalVar += 1
	globalVar += 1

	hash := hashes[fmt.Sprintf(keyPattern, indicies[0], indicies[1], indicies[2])]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&charactersResponse{Indices: indicies, Hash: hash, Number: passwordNumber})
}

func main() {
	updatePassword()

	log.Printf("Password is %s", keyPattern)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/source", sourceHandler)
	http.HandleFunc("/docker", dockerHandler)
	http.HandleFunc("/password", passwordHandler)
	http.HandleFunc("/characters", charactersHandler)

	reset, _ := time.ParseDuration("10s")
	ticker := time.NewTicker(reset)

	go func() {
		for range ticker.C {
			updatePassword()
		}
	}()

	log.Fatal(http.ListenAndServe(":9000", nil))
}


```

Unfortunately, I wasn't able to solve this during the challenge. However, later on with the help of the write-up from the challenge author, I was able to solve it. The write-up explains that...

```text
Hash all the 3 letter combinations, keep making requests to /characters until you've seen every index
```

So my solution includes a loop which finds all the possible combination of characters `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` and finding its sha1 hash. 

Later brute forcing indices using the `/characters` to find the hash from the dictionary which we have already created and mapping those characters with the index in our password. In order to find the hash within the short duration of 10 seconds I used concurrency. 

```python
from hashlib import sha1
import requests
import concurrent.futures

letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
letter_arr = [char for char in letters]
hash_list = {}
password = ['' for i in range(32)]
sum = 0
URL = "https://three.ictf.iciaran.com/characters"

for i in range(52):
	for j in range(0,52):
		for k in range(0,52):
			chars = letter_arr[i]+letter_arr[j]+letter_arr[k]
			hash_list[sha1(chars.encode()).digest().hex()] = chars
   

def get_chars(hash):
    return hash_list.get(hash)

def find_chars():
    response = requests.post(URL).json()
    hash = response.get('hash')
    indices = response.get('indices')
    
    hashed = get_chars(hash)
    password[indices[0]] = hashed[0]
    password[indices[1]] = hashed[1]
    password[indices[2]] = hashed[2]

if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        while '' in password:
            futures = [executor.submit(find_chars) for _ in range(10)]
            concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
    
    password = ''.join(password)
    req_data = {"password":password}
    res = requests.post("https://three.ictf.iciaran.com/password",data=req_data)
    print(res.text)

```

We won't get the output if the password is updated midway while the script is running. However, by attempting it a few times, we should be able to find the flag.

```bash
python3 solve.py
Flag: ictf{00ps_th1s_1s_jus7_l0ts_0f_thr33_l3tt3r_p4ssw0rds}
```

