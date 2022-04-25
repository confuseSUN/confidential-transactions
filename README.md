# confidential transaction


![image](https://user-images.githubusercontent.com/39479965/165015381-72cb30dd-423c-4a9d-b8dc-969882e04925.png)

    通常一笔交易包含多个输入和多个输出， 输入是来自其他交易的输出，在交易金额是明文的情况下很好验证这笔交易的有效性，但如果交易金额是
    密文呢，也即输入是x,y,z，输出是p、q，这时候该如何验证呢？其实验证也很简单, 只要保证x+y+z = p +q 就行，即输入的和 = 输出的和，
    输入100，输出肯定也得100，如果是101，就凭空创造了1块钱的财富，所以我们不需要知道输入输出具体金额，只要能验证输入等于输出，确保这
    笔交易没有凭空创作财富就行，但这样还不够，如下面这笔交易：
                                       100 = 200 -100 
    输入100，输出200 和-100 ，满足输入等于输出，对于-100这笔交易可以抛弃，对于200的输出相当于凭空创造了100的财富，所以我们还必须
    限制交易输出必须为正数。
    
    程序实现两个demo.位于test目录下
    
    


   ## demo1： 机密性交易 （cargo run -p confidential_transaction）
   机密性交易主要实现以下两个机密性：
   1. 隐藏交易金额
   2. 保护接收方地址  
       
   使用技术：
   ### 基于零知识证明的pederson commitment和证明
![image](https://user-images.githubusercontent.com/39479965/163909013-7faae42c-920e-4064-bce7-070495a853d2.png)

上面算法实现了pederson commitment 乘积证明，基于此，本文对上面算法进行改造，实现一种pederson commitment和证明，并基于fiat shamir变换思想，变交互式证明为非交互式，
pederson commitment和证明能够证明输入和输出关系，相对于pederson commitment加法同态性质，其在盲化因子的选择上更具随机性，pederson commitment和证明算法如下：
![1650332986367_A70E8C4B-3975-492d-A48D-61A1A251B5F0](https://user-images.githubusercontent.com/39479965/163909495-b933ef26-4fce-4201-9861-9123df5d270f.png)



  ### 一次性地址

![image](https://user-images.githubusercontent.com/39479965/162351684-0a0d7901-31c8-41fb-8811-37d61bf87613.png)

门罗币中使用两个公钥去构造一次性地址，本算法对此进行了优化将两个公钥减少为一个，计算更加高效  

![image](https://user-images.githubusercontent.com/39479965/163910805-d261a47b-5f81-4825-a428-e762de08cca5.png)
  
  ### ECDH密钥交换		
  基于上述一次性地址，再结合ECDH算法，生成一个对称密钥加密明文金额  
  ![image](https://user-images.githubusercontent.com/39479965/163910923-29b94d0c-877a-4c84-a54d-a138ae4820b9.png)
  
     
   ## demo2： 环机密性交易 （cargo run -p ring_confidential_transaction）
  环机密性交易主要实现以下三个机密性：
   1. 隐藏交易金额
   2. 保护接收方地址  
   3. 保护接收方地址
   
   ### MLSAG：多层可链接环签名
   MLSAG是在LSAG基础上进行改进，目的是为了支持多输入。
   多层：即支持多输入
   可链接：通过关联标签可以判断两个不同环签名是否由同一用户生成，可用于防止双花
   具体算法实现见附录
   
   ### MLSAG保护接收方地址上的应用
    
    如果直接选择若干个一次性地址构成环，进行环签名，则起不到隐藏发送方的作用，因为每个一次性地址拥有的pederson commitment不一样，
    很容易根据pederson commitment找出环中实际的发送方，所以环签名失效
        
   ### 改进1:
![image](https://user-images.githubusercontent.com/39479965/165031253-a93ef2c2-a788-48ec-99ef-b765a30ed792.png)  
 发送方计算得到zG, 并以z作为私钥，zG作为公钥，并计算其他成员的公钥（无法得知其私钥），如下图红色区域，并以红色区域
 构成一个环进行环签名  
![image](https://user-images.githubusercontent.com/39479965/165031383-850b0cc3-fc9e-4efb-93ac-3548d4c7d630.png)
     
  但改进1 依然存在问题，如果只是以红色区域构成环，那么发送方每次选择不同盲化因子，那么key_images（关联标签）也会变化，不能抵制双花
   ### 改进2: 再上原来的密钥，一起构成环（完美！！！）
   ![image](https://user-images.githubusercontent.com/39479965/165033237-dbec5332-5f70-47bd-b795-ee9e5360d654.png)

     
   
   ## 附录：MLSAG
   ![image](https://user-images.githubusercontent.com/39479965/165029007-8eee8b80-6dc2-4b8e-9643-76de8b51be8b.png)
![image](https://user-images.githubusercontent.com/39479965/165029068-1de7f652-ac46-437d-902c-fb93df680400.png)

