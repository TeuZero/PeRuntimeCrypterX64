# PeRuntimeCrypterX64
Muito simples, pega o endereço da função MessageBoxA com getprocaddress, escreve o endereço na IAT do seu programa, Obs: Só foi testado compilado com VisualStudio, Montando seu programa com os código do C/C++. ele faz issso depois de injetado, ele importa a função, com um shellcode que vai junto injetado. Depois de importar, é dado um salto pro entrypoint do seu programa, e executa a MessageBoxA do seu programa.Isso é só uns dos começos,exemplos, de como montar um Runtime Crypter, bem fácil.
Existem outras tecnicas mais essa foi umas das mais fáceis que achei.
