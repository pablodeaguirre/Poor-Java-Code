#!/bin/bash

mkdir -p bin
#rm bin/*
javac -cp lib/wgssSTU-1.0.0.jar src/main/java/* -d bin/
java -Djava.library.path=/usr/local/lib -cp bin/:lib/wgssSTU-1.0.0.jar DemoButtonsMultimage true E24B 10
eog sig.png 

