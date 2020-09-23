<head>
<style>
.nutrisafe {
  background: #193954 url(https://www.nutrisafe.de/wp-content/themes/nutrisafe/img/pattern-gro%C3%9F-wei%C3%9F-emvy.png) repeat;
}
</style>
</head>
<div class="nutrisafe">
	<img src="https://www.nutrisafe.de/wp-content/themes/nutrisafe/img/NutriSafe_Logo.svg"/>
</div>

# REST API #

The NutriSafe REST API is the interface to the NutriSafe Distributed Ledger Network for organizations. You can read, write, update, create and delete objects in the blockchain network with simple commands and even define new object types (so called meta objects). Furthermore different roles from different use cases of an organization can be mapped to users with customizable access rights for all chaincode functions.

Possible use cases include, but are not limited to:
* read access for the company's management dashboard
* automatic creation of new virtual products by supported machines (after physically creating a product)
* manual updates of product attributes by certified laboratories
* tracing product origins on the underlying supply chains

## Features ##

We continuously work on and extend the REST API. Combined with the NutriSafe Distributed Ledger Network the following incomplete feature list might give you at least an idea about the capabilities:
* creating, deleting, updating and reading objects from the chain
* definition of new object types and possible attributes (meta objects)
* user management with roles and user assignable whitelists for restricting chaincode calls
* authentication with bruteforce force protection
* filtered selection of object IDs

## Installation ##

We plan on making a simple setup for this (a docker container or installer), but for now you need to set it up by yourself. However we do not leave you alone with this task, so here is your checklist:

1. Download or clone the **GitHub code** and make sure you satisfy all dependencies ([Hyperledger Fabric Gateway](https://github.com/hyperledger/fabric-gateway-java "Hyperledger Fabric Gateway API on GitHub"), [Spring Boot](https://spring.io/projects/spring-boot "Spring Boot Project"), [Spring Security](https://spring.io/projects/spring-security "Spring Security Project"),...). Copy the [**certificates and private keys**](https://hyperledger-fabric.readthedocs.io/en/latest/identity/identity.html "Identity management of Hyperledger Fabric") of your organization's network registration into your [resource folder](https://github.com/dl-ota/Nutrisafe-REST-API/tree/master/src/main/resources "The resource folder").
2. Configure your [**connection json file**](https://github.com/hyperledger/fabric-gateway-java/blob/master/src/test/java/org/hyperledger/fabric/gateway/connection.json "Example file for a connection configuration") for the Hyperledger Fabric Gateway API inside your resource folder with details about the peers that you want to connect to. Make sure to only use peers of a compatible network like the NutriSafe Distributed Ledger Network.
3. Install and run an empty [**PostgreSQL database**](https://www.postgresql.org/download/ "PostgreSQL download") for the REST API's user management and remember your credentials.
4. Setup a custom profile for your REST API under the resource folder in **[application.yml](https://github.com/dl-ota/Nutrisafe-REST-API/blob/master/src/main/resources/application.yml "Example profile")**. This will contain your registered organization name, your database credentials, the name of your connection file and some more network information like your channel name and your certificate and private key file names.
5. Make sure the correct profile name is set in **[application.properties](https://github.com/dl-ota/Nutrisafe-REST-API/blob/master/src/main/resources/application.properties "Example properties file")** and, if you wish, use even more options here for further customization (e.g. for changing the port).

Compile and you should be ready to go!

## Usage ##

The REST API offers the following basic commands:

### .../auth ###
This command is used for your authentication. Send a POST request with a JSON object in its body containing your username and password in order to receive a JWT token. You need this token for the authorization of other API calls.

**Example:**

Body content in your POST request:

	{'username':'TLJohnson','password':'example_pw12345!'}

Response:

	{'username':'TLJohnson','token':'eyJhb...'}

Usage in the header of other API calls:

	Content-Type:application/json
	User-Agent:Mozilla
	Accept:*/*
	Authorization: Bearer eyJhb...

### .../get ###
This command retrieves different information from the chaincode or from the REST API's user management. Arguments are applied as URL parameters ("args").

The following example commands are getting forwarded to the chaincode:

* Default role "user" (read access):

		.../get?function=objectExists&args=MILK5463
	<!-- next code line -->
		.../get?function=privateObjectExists&args=MILK5463,secretcollection
	<!-- next code line -->
		.../get?function=readObject&args=MILK5463
	<!-- next code line -->
		.../get?function=readAccept&args=ORG1,secretcollection
	<!-- next code line -->
		.../get?function=META_readMetaDef

The following example commands are directly handled by the REST API:

* Default role "user" (read access):

		.../get?function=getUserInfo

* Default role "admin" (admin access):

		.../get?function=getUserInfoOfUser&args=TLJohnson
	<!-- next code line -->
		.../get?function=getAllUsers
	<!-- next code line -->
		.../get?function=getWhitelists

### .../select ###
This command select different information from the chaincode by applying a query. This allows to search for objects which comply with a certain filter strategy.

### .../submit ###
This command writes information to the chaincode or to the REST API's user management. Arguments are given as JSON-formatted body content.

The following example commands are getting forwarded to the chaincode:

* Default role "member" (write access):

		.../submit?function=createObject
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463','pdc':'secretcollection','productName':'milk','attributes':['label','cow','fat'],'attrValues':['organic','JackyRoseMilly','8.3'],'amount':'2.3','unit':'liter'}
	---
		.../submit?function=deleteObject
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463'}
	---
		.../submit?function=setReceiver
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463','receiver':'Org2','pdc':'secretcollection'}
	---
		.../submit?function=changeOwner
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463'}
	---
		.../submit?function=addPredecessor
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463','preIds':['MILK54', 'MILK63']}
	---
		.../submit?function=updateAttribute
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463','attrName':'fat','attrValue':'8.4'}
	---
		.../submit?function=addRuleNameAndCondition
	<!-- next code line -->
	- Example body content:
	
			{'pdc':'secretcollection','product':'milk','autoAccept':'true'}
	---
		.../submit?function=deleteRuleForProduct
	<!-- next code line -->
	- Example body content:
	
			{'pdc':'secretcollection','product':'milk'}
	---
		.../submit?function=activateAlarm
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463'}
	---
		.../submit?function=exportDataToAuthPDC
	<!-- next code line -->
	- Example body content:
	
			{'id':'MILK5463'}

* Default role "admin" (admin access):

		.../submit?function=META_createSampleData
	---
		.../submit?function=META_addAttributeDefinition
	<!-- next code line -->
	- Example body content:
	
			{'attribute':'fat','datatype':'float'}
	---
		.../submit?function=META_addProductDefinition
	<!-- next code line -->
	- Example body content:
	
			{'productname':'butter','attributes':['fat']}

The following example commands are directly handled by the REST API:

* Default role "admin" (admin access):

		.../submit?function=createUser
	<!-- next code line -->
	- Example body content:
	
			{'username':'TLJohnson','password':'example_pw12345!'}
		(Role defaults to users with 'USER_ROLE'. Whitelists default to standard whitelists according to the chosen role.) Another example:
		
			{'username':'TLJohnson','password':'example_pw12345!','role':'ROLE_MEMBER','whitelist':'MY_CUSTOM_WHITELIST'}
		In this example the role **and** the whitelist has been explicitly set.
	---
		.../submit?function=deleteUser
	<!-- next code line -->
	- Example body content:
	
			{'username':'TLJohnson'}
	---
		.../submit?function=setRole
	<!-- next code line -->
	- Example body content:
	
			{'username':'TLJohnson','role':'ROLE_MEMBER'}
	---
		.../submit?function=createWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST'}
	---
		.../submit?function=deleteWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST'}
	---
		.../submit?function=linkFunctionToWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST','function':'createObject'}
	---
		.../submit?function=unlinkFunctionFromWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST','function':'createObject'}
	---
		.../submit?function=linkUserToWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST','username':'TLJohnson'}
	---
		.../submit?function=unlinkUserFromWhitelist
	<!-- next code line -->
	- Example body content:
	
			{'whitelist':'MY_CUSTOM_WHITELIST','username':'TLJohnson'}

## License ##

TODO!

## Third party ##

TODO!