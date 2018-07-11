Autores: 
Daniel Soneira Rama
Santiago Salvador Rodríguez
José Antonio Álvarez Fernández

**********************************************************************************************************************************
******************Instruccions para o uso do servicio de cifrado desenrolado para a asignatura de seguridade**********************
**********************************************************************************************************************************

Lanzamento das diferentes clases que compoñen o programa, neste orde e cos parametros indicados:

  1.- TSA: java TSA

  2.- Servidor: java Servidor keyStoreFile keyStorePassword trustStoreFile trustStorePassword algoritmo_de_cifrado

  3.- Cliente: java Cliente keyStoreFile trustStoreFile

Valores por defecto dos diferentes parámetros:

  keyStoreFile = "KS_Servidor" ou "KS_Cliente" segundo estemos executando o servidor ou o cliente.
  trustStoreFile = "TS_Servidor" ou "TS_Cliente" segundo estemos executando o servidor ou o cliente.
  keyStorePassword = trustStorePassword = "servidor"

A ter en conta:

  - Ao comezo da execucion do cliente pídesenos a introducción do contrasinal de keyStore e TrustStore, o cal é "cliente"
  - As operacións soportadas escríbense por comando (REGISTRAR_DOCUMENTO, RECUPERAR_DOCUMENTO, LISTAR_DOCUMENTOS ou SALIR)
  - Os algoritmos de cifrado soportados no servidor son AES ou ARCFOUR (escribir literalmente)
  - A hora de utilizar a funcionalidade REGISTRAR_DOCUMENTO:
    - O id de usuario que se utiliza por defecto é soneira, pois é o nome ao que están os certificados. Creando certificados
      novos non habería problema en utilizar outro id.
    - Cando se pide o nome do arquivo a cifrar, a ruta por defecto na que debe estar o arquivo e en Recursos/Cliente/. Nos só
      temos que introducir o nome, eso sí, extensión incluida.
    - Utilizar por defecto firma DSA (escribir "dsa" cando se pida)
