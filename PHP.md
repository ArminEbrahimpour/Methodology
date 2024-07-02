

## PHP classes and objects 

### there is multiple types of visiblity in php
#### public : anywhere of the code can access to the value of a public variable 
	class foo {
			public $foo = "sth";
	}
	$f = new foo();
	echo $f -> foo;
##### the output is "sth"
### private : only the value is reachable inside the class code 

	class Foo {
		private $bar = "sth";
	}
	$f = new Foo();
	echo f->bar;
##### the output is "Fatal error"

### protected : can be accessed by the class that defines the property or method and by inheriting and parent classes.

	class Foo extends Bar{
		protected $foo = "foo";
		function getbar() {return $this->bar;}
	}
	class Bar{
		protected $bar = "bar";
		function getfoo() {return this->foo;}
	}
	$f = new Foo();
	echo $f->getfoo();
	echo $f->getbar();

#### Magic Methods :

#### 1.`__construct(...args)` : called when creating an instance of a class

#### 2.`__destruct()` : calling when destroying an instance of a class

#### 3.`__call(string $name, array $arguments)` : is triggered when the method/ function doesn't exist.

#### 4.`__get(string $name)` : get/set (property access methods)

#### 5.`__set(string $name, string $value)

#### 6.`__wakeup()`: only triggered when deserializing string and re-instantiating an object. 

#### 7.`__toString()` : is called when the object is converted to a string via printing or concatenating. it's an alternative to destruct or wakeup functionality

#### note : you have to define these magic methods public


### NameSpaces: are typically used in a file to subset further classes 

### Note : php is an interpreted language and used in a object oriented way, it needs a way to dynamically load classes at runtime. this is known in php as autoloader.
### AutoLoader:

	function __autoloader($class){
		$fileName = "class/". $class . ".php";
		include_once($fileName);
	}
	new InexistentClass;

## PHP Reflection
#### to invoke methods classes(constructors), trigger propery access, dynamically change access modifires in runtime .

#### classes that allow reflection :
`class Reflection`
`interface Reflector`
`....`
#### Note : php > 8.0 encourage developers to use more reflection.

	$func = new
	ReflectionFunction($__GET['func_name'])
	$func->invoke();

	/vuln.php?func_name=phpinfo


## PHP Typing 

#### there are two type comparison callsed `loose` and `strict`

#### loose comparison:
	==
	!=
#### note : what loose comparison means is if you are comparing two different types it tries to joggle the type .
		php > var_dump("1" == 1); // turns "1" to an integer 
		bool(true)
		var_dump(-1 == true); //
		bool(true)

![](statics/PHP-type-joggling(loose-comparison).png)

	php > var_dump(0e12345 == 0);
	bool(true)
	php > var_dump("1337jshdfaldj;j" == 1337);
	bool(true)
	php > var_dump("jshdflkalkjdlask" == 0);
	bool(true)

#### NOTE : this type of attacks called `Type juggling` attacks like this reduce the number of attempts needed for brute forcing .

#### NOTE : some common places to look for them are in password resets, csrf token checks and authentication processes(tokens, credentials, etc).


#### the following code is vulnerable 
	$api_key = substr(md5(mt_rand()), 0, 1);
	if(isset($_cookie['api_key'])&& $_cookie['api_key'] == $api_key){
		// access to privilege area
	}
#### if both values are strings yet both are numbers, php will attempt to compare them as numbers!
#### so how about this snippet of code ?
	$api_key = substr(md5(mt_rand()), 0, 1);
		if(isset($_cookie['api_key']) && strcmp($_cookie['api_key'] , $api_key) == 0){
		// access to pribilege area
		}
#### NOTE That In this code we still have loose comparison and if instead of a string as a cookie api_key attacker inputs an null the function strcmp() returns a warning and in loose comparison the type juggling occurs and the condition passes.

#### Strict comparisons :
1. ===
2. !==

#### strict comparisons do not do any juggling of types.

![](/statics/PHP-strict-comparison-table.png)


## PHP Debugging :

#### as far as php is interpreted language, we can modify source code(unless its encrypted )

	die("I'm in this function!");
	die will stop execution and print the value inside
	print_r($something_complex);
	print_r prints the variable value in human-readable form to stdout

	get_defined_vars(); // this function gets all the defined variables 
	// including built-ins and custom variables

	  debug_zval_dump(); // this function dumps the variable with its refrence counts. this is helpful when there are multiple paths to update a single reference


### php encryption :


#### sometimes you may come up  against source code that is encrypted with :
1. ionCube
2. etc...

#### they install php module into the runtime to perform the encryption and decryption.
#### for defeating ioniCube there is a website https://easytoyou.eu/ .


### PHP prototyping

#### there is a site called 3v4l.org which you can test some php scripts . but it would be public after submit.

### PHP Error Reporting 
#### you can enable error reporting in your scripts to see all fatal errors and warnings : 
	error_reporting(E_ALL);
#### also, instead making hard changes to your php.ini file, you can enable display_errors by simply using `ini_set` 
	ini_set('display_errors', 1);


### PHP Dynamic Evaluation 

#### command execution is different than code execution , code execution just typically executes arbitrary commands as a method of exploition.

#### the php.ini file can disable system commands using disable_functions!

	disable_functions = exec, passthru, shell_exec, system...

#### How do we defeat it ?
1. use a code execution vulnerablility to break out of the virtual machine! (memory corruption)

2. Find a new method that executes commands that is unblocked 

3. Use write methods to overwrite scripts/executables and trigger execution from a different environment.
