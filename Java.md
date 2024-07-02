## JVM (java virtual machine)
#### the jvm is an abstract machine. It's a specification that provides a runtime environment in which java bytecode can be executed.


![](/statics/java-jvm.png)


## java frameworks 

#### spring
#### hibernate
#### google web toolkit 

#### Struts


## Application input 

#### it depends on java frameworks in use .

	@Controller 
	@RequestMapping("books")
	public class SimpleBookController {
		@GetMapping("/{id}", produce = "application/json")
		public @RsponseBody Book getBook(@PathVariable int id) {
			return findBookById(id);
		}
	}

the above snippet code is spring code 


#### Struts 

	public class LoginAction extends Action {
		@Override
		public ActionForward execute(ActionMapping mapping, ActionForm form,HttpServletRequest request, HttpServletResponse response) throws Exception {
			LoginForm loginForm = (LoginForm) form;
		}
	}
	public class LoginForm extends ActionForm


#### for low level input the following classes are used often:
1. ServletRequest
2. HttpServletRequest

#### the ServletRequest class is the lowest access to request data.
##### some examples for api uses :
ServletRequest.getParameter("filename");
ServletRequest.getContentLength();
ServletRequest.getInputStream();

#### the HttpServletRequest `subclasses` ServletRequest :

HttpServletRequest.getCookie();
HttpServletRequest.getContextPath();
HttpServletRequest.getHeaders("UserAgent");


## JAVA Debugging 

#### as long as java is a compiled and such as needs proper debugging to understand flow.

#### How ever you can modify the bytecode of the applications class files. Burp suite Infiltrator does this :

##### note : never install eclipse from package managers or from the given installers.
