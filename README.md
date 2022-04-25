# confidential transaction

cargo run -p confidential_transaction  /  cargo run -p ring_confidential_transaction

![image](https://user-images.githubusercontent.com/39479965/165015381-72cb30dd-423c-4a9d-b8dc-969882e04925.png)

    通常一笔交易包含一个输入和多个输出， 输入是来自其他交易的输出，在交易金额是明文的情况下很好验证这笔交易的有效性，但如果交易金额是在密文情况下，也即输入是x,y,z，输出是p、q，这时候该
    如何验证？其实验证也很简单, 只要保证x+y+z = p +q 就行，即要求输入的和 = 输出的和，输入100，输出肯定也得100，如果是101，就凭空创造了1块钱的财富，所以我们不需要知道输入输出具体金
    额，只要能验证输入等于输出，从而确保了这笔交易没有凭空创作财富，但这样还不够，如下面这笔交易：
                                       100 = 200 -100 
    输入100，输出200 和-100 ，满足输入 = 输出的和，对于-100这笔交易可以抛弃，对于200的输出相当于凭空创造了100的财富，所以我们还必须限制交易输出必须为正数。

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

