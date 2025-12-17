while condicion
do 
	cosas
done

condiciones: $n -eq(uals) 3, $n -lt(less than) 3, -ne (not equals)


read --> pedir información, la almacena en $REPLY
read -p v1 v2--> prompt para pedir información, le puedes pasar varias variables


if \[ condicion \]
then
	cosas
fi

case expresion in
	opcion 1)
		cmd1;;
	opcion 2)
		cmd2;;
	\*)
		cmd3;;
esac

\* es el default


for dia in $(cat dias)
do
	echo $dia
done


bc --> calculadora


function print_arg { 
	echo '$# = ' $#
	for i in $*
	do
		echo $i
	done
}




