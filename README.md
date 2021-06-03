![MetaHL Fabric](https://github.com/OTARIS/MF-REST-API/blob/master/logo.png "MetaHL Fabric Logo")

# REST API #

The MetaHL Fabric REST API is an interface to a Hyperledger® Fabric network for organizations. It originates from the [NutriSafe](https://nutrisafe.de/ "NutriSafe") research project and is part of its official toolkit. Combined with the [MetaHL Fabric Chain Code](https://github.com/OTARIS/MF-Chaincode/ "MetaHL Fabric Chain Code") you can read, write, update, create and delete objects in the blockchain network with simple commands and even define new object types (so called meta objects). Furthermore different roles from different use cases of an organization can be mapped to users with customizable access rights via the REST API for all chaincode functions.

Possible use cases include, but are not limited to:
* read access for the company's management dashboard
* automatic creation of new virtual products by supported machines (after physically creating a product)
* manual updates of product attributes by certified laboratories
* tracing product origins on the underlying supply chains

## Features ##

We continuously work on and extend the REST API. Combined with the [MetaHL Fabric Chain Code](https://github.com/OTARIS/MF-Chaincode/ "MetaHL Fabric Chain Code") the following incomplete feature list might give you at least an idea about the capabilities:
* creating, deleting, updating and reading objects from the chain
* definition of new object types and possible attributes (meta objects)
* user management with roles and user assignable whitelists for restricting chaincode calls
* authentication with bruteforce force protection
* filtered selection of object IDs

## Installation ##

Before you start the REST API make sure your network is set up. Check out the [MetaHL Fabric Chain Code](https://github.com/OTARIS/MF-Chaincode/ "MetaHL Fabric Chain Code") for more information. In order to run the MetaHL Fabric REST API, here is your checklist:

1. Configure your own [**connection json file**](https://github.com/hyperledger/fabric-gateway-java/blob/master/src/test/java/org/hyperledger/fabric/gateway/connection.json "Example file for a connection configuration") for the Hyperledger Fabric Gateway API with details about the peers that you want to connect to.
2. Install and run an empty [**PostgreSQL database**](https://www.postgresql.org/download/ "PostgreSQL download") for the REST API's user management and remember your credentials.
3. Setup a custom profile for your REST API by simply filling out this [**template**](https://github.com/OTARIS/MF-REST-API/blob/master/templates/application.yml "Example profile"). This will contain your registered organization name, your database credentials, the name of your connection file and some more network information like your channel name and your certificate and private key file names.
4. Start the REST-API with the environment variable "**MF_PROPERTIES**" set. This variable needs to contain the path to your application.yml (the file of step 3).

Now you should be ready to go!

## Usage ##

The REST API offers the following basic commands:

### POST .../auth ###
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

### GET .../get ###
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

### POST .../select ###
This command selects different information from the chaincode or the user database by applying a query. This allows to search for objects and user info which comply with a certain filter strategy. You need to send the what parameter in order to specify what you are looking for. Then define conditions for filtering the result in a JSON-format in the body content. These conditions are "and"-combined. For example the following request would ask for all usernames starting with "a" and having any role that contains the word "admin":

		.../select?what=username
		
	<!-- next code line -->

	- Example body content:

			{'username':'a%','role':'%admin%'}

### POST .../submit ###
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

   Copyright 2021 OTARIS Interactive Services GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


## Third party ##

TODO!
