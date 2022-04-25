# confidential transaction

cargo run -p ct_test

一. 基于零知识证明的pederson commitment和证明
![image](https://user-images.githubusercontent.com/39479965/163909013-7faae42c-920e-4064-bce7-070495a853d2.png)

上面算法实现了pederson commitment 乘积证明，基于此，对上面算法进行改造，实现pederson commitment和证明，算法如下：
![1650332986367_A70E8C4B-3975-492d-A48D-61A1A251B5F0](https://user-images.githubusercontent.com/39479965/163909495-b933ef26-4fce-4201-9861-9123df5d270f.png)


二. 一次性地址

![image](https://user-images.githubusercontent.com/39479965/162351684-0a0d7901-31c8-41fb-8811-37d61bf87613.png)

基于此，优化一次性地址，将两个密钥减少为一个，计算更加高效  

![image](https://user-images.githubusercontent.com/39479965/163910805-d261a47b-5f81-4825-a428-e762de08cca5.png)
  
		
三. 基于上述一次性地址，再结合ECDH算法，生成对称密钥，用于加密明文金额  
  ![image](https://user-images.githubusercontent.com/39479965/163910923-29b94d0c-877a-4c84-a54d-a138ae4820b9.png)

