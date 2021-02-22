# CheckPointAPI
# Was written by Asaf 'Glitch' Shitrit
# For the best team in the world.
# ALL HAIL CHECKPOINT !


import urllib3
import requests
import queue
import json
import time
import ipaddress  # Works on python 2.7
import threading

RULE_CSV_HEADERS = 'Number,Enabled,Name,Tracked,Creation Time(UNIX)'

# Object Types
TYPE_HOST = 'host'
TYPE_NETWORK = 'network'
TYPE_GROUP = 'group'
TYPE_GW_CLUSTER = 'CpmiGatewayCluster'
TYPE_GW_CLUSTER_MEMBER = 'CpmiClusterMember'
TYPE_GW_HOST = 'CpmiHostCkp'
TYPE_ANY = 'CpmiAnyObject'
TYPE_ANY_VALUE = 'ANY'
TYPE_ADDRESS_RANGE = 'address-range'
SERCURE_GATEWAYS_GROUP = 'Secure_Gateways'

# Rule Actions
ACTION_DROP = 'Drop'
ACTION_ACCEPT = 'Accept'

# Service Types
SERVICE_TCP = 'service-tcp'
SERVICE_UDP = 'service-udp'
SERVICE_DCE_RPC = 'service-dce-rpc'
SERVICE_OTHER = 'service-other'
SERVICE_ICMP = 'CpmiIcmpService'
SERVICE_GROUP = 'service-group'
# Service Types Array
SERVICE_TYPES = [SERVICE_TCP, SERVICE_UDP, SERVICE_DCE_RPC]


class NoSessionException(Exception):
	"""
	This exception is raised when a function of this Lib
	is called before using the 'Login' function and loggin in
	to the CMA using valid credentials.
	"""

	def __init__(self):
		self.msg = "No active session was found, please use the Login function before calling any other function"
		self.code = 2


class NoIdentifierException(Exception):
	"""
	This exception is raised when a function that requires an identifier
	UID or Name is called but none is given to it
	"""

	def __init__(self):
		self.msg = "No Identifier was supplied (UID or Name)"
		self.code = 32


class RuleGetError(Exception):
	def __init__(self, rule_num=''):
		self.msg = "Failed to get rule {} data from CMA".format(rule_num)
		self.code = 11


class Gateway:
	"""
	The gateway class depicts a Single Firewall (or cluster)
	Props:
		name(string) - gateway name
		ip(string) - ip address (x.x.x.x format)
		uid(string) - the object CMA uid
		gw_type(string) - gateway type (cluster or single)
	"""

	def __init__(self, name, ip, uid, gw_type):
		self.name = name
		self.ip = ip
		self.uid = uid
		self.gw_type = gw_type

	def __str__(self):
		return '\t {} - {} - {} - {}'.format(self.name, self.ip, self.uid, self.gw_type)


class Host:
	"""
	The host class depicts a Host object in the CMA
	Props:
		name(string) - host name
		ip(string) - ip address (x.x.x.x format)
		uid(string) - the object CMA uid
	"""

	def __init__(self, name, ip, uid):
		self.name = name
		self.ip = ip
		self.uid = uid

	def __str__(self):
		return '\t {} - {} - {}'.format(self.name, self.ip, self.uid)


class Group:
	"""
	The group class depicts group of objects i.e hosts,networks,services
	Props:
		name(string) - host name
		members(array) - an array of objects (can be hosts,networks,services)
		uid(string) - the object CMA uid
	"""

	def __init__(self, name, members, uid):
		self.name = name
		self.members = members
		self.uid = uid

	def __str__(self):
		return '\n'.join(map(lambda member: str(member), self.members))


class Network:
	"""
	The Network class depicts a network in the CMA
	Props:
		name(string) - network name
		net_id(string) - the network id (example : 192.168.1.0)
		subnet_mask(string) - network subnet mask (example : 255.255.255.0)
		uid(string) - the object CMA uid
	"""

	def __init__(self, name, net_id, subnet_mask, uid):
		self.name = name
		self.net_id = net_id
		self.subnet_mask = subnet_mask
		self.uid = uid

	def getMaskBytes(self):
		return 8 * len(filter(lambda octat: octat == '255', self.subnet_mask.split('.')))

	def __str__(self):
		return "\t {} - {} / {}".format(self.name, self.net_id, self.subnet_mask)


class AddressRange:
	"""
	The AddressRange class depicts an address range obj in the CMA
	Props:
		name(string) - address range name
		net_id(string) - the network id (example : 192.168.1.0)
		subnet_mask(string) - network subnet mask (example : 255.255.255.0)
		uid(string) - the object CMA uid


	Extra Info:
		I decided to work with the "ipaddress" lib, really
		nice for taking an ip address and working with it.
		checking if something is in its range for example.
	"""

	def __init__(self, name, ipv4_address_start, ipv4_address_end, uid):
		self.name = name
		self.ipv4_address_start = ipv4_address_start
		self.ipv4_address_end = ipv4_address_end
		self.uid = uid

	def __str__(self):
		return "\t {} - {}".format(self.ipv4_address_start, self.ipv4_address_end)


class Any:
	def __init__(self):
		self.name = 'ANY'

	def __str__(self):
		return self.name


class Rule:
	def __init__(self, rule_num, enabled, name, sources, destinations, track, creation_time_long, services, action):
		self.rule_num = rule_num
		self.enabled = enabled
		self.name = name
		self.track = track  # Either Log\None
		self.creation_time_long = creation_time_long
		self.sources = sources
		self.destinations = destinations
		self.services = services  # aka ports
		self.action = action

	def __str__(self):
		formatted_sources = '\n'.join(map(lambda source: str(source), self.sources))
		formatted_destinations = '\n'.join(map(lambda dest: str(dest), self.destinations))
		formatted_services = '\n'.join(map(lambda service: str(service), self.services))

		return "Number : {}\nEnabled : {}\nName : {}\nTracked : {}\nCreation Time (UNIX) : {}\nSources :\n{}\nDestinations :\n{}\nServices : \n{}\n" \
			.format(self.rule_num, self.enabled, self.name, self.track, self.creation_time_long, formatted_sources,
		            formatted_destinations, formatted_services)

	def toCSV(self):
		return "{},{},{},{},{}".format(self.rule_num, self.enabled, self.name, self, self.sources, self.destinations,
		                               self.services, self.tracked, self.action, self.creation - time)


class Service:
	def __init__(self, name, service_type, uid, ports=[], ip_protocol=-1):
		self.name = name
		self.ports = ports
		self.ip_protocol = ip_protocol
		self.uid = uid
		self.service_type = service_type

	def __str__(self):
		if self.service_type == SERVICE_ICMP:
			# Service ICMP specific
			return "\t Name : " + self.name
		if self.service_type == SERVICE_OTHER:
			# Service other specific
			return "\t Name : {} IP protocol : {} Type : {}".format(self.name, self.ip_protocol, self.service_type)
		if self.service_type == SERVICE_DCE_RPC:
			# Service other specific
			return "\t Name : {} Type : {}".format(self.name, self.service_type)

		# Regular TCP/UDP,DCE/RPC services 
		# --------------------------------
		# Formatting of the ports to a nice format
		if len(self.ports) == 1:
			formatted_port = str(self.ports[0])
		else:
			formatted_port = str(self.ports[0]) + '-' + str(self.ports[-1])

		return "\t Name : {} Port : {} Type : {}".format(self.name, formatted_port, self.service_type)


class Connection:
	MAX_QUERY_LIMIT = 500

	def __init__(self, ip_address, port, verbose=False):
		"""
		Connection is the class that manages the connection to the CMA,
		by using the login function you create a session in fron of the CMA.
		after doing that you can continue using any other functions to get the
		data you want.
		this function just takes an ip address and a port and inits it,
		great great great overall.
		Args:
			ip_address(string) - ip address
			port(int,string) - port number

		"""
		if (type(port) == int): port = str(port)
		self.url = r"https://" + ip_address + ":" + port + r"/web_api/"
		self.verbose = verbose
		requests.packages.urllib3.disable_warnings()

	def login(self, username, password):
		"""
		Login Function that creates a logon session
		on the CMA and returns a Session ID (SID)
		Args:
			username (string) - A username that exists in the CMA
			password (string) - The relevent username password
		Returns:
			sid (string) - The session identifier
		"""
		LOGIN_URL = self.url + "login"
		data = {'user': username, 'password': password}

		r = requests.post(LOGIN_URL, verify=False, json=data)
		if self.verbose:
			print(r.text)
		try:
			self.sid = json.loads(r.text)['sid']
			self.log_time = int(time.time())
			return self.sid
		except KeyError:
			self.sid = ''
		return False

	def logout(self):
		"""
		Login Function that creates a logon session
		on the CMA and returns a Session ID (SID)
		Args:
			None
		Returns:
			status (boolean) - if the logout was sucessfull or not
		"""

		if not self.__sid_check__():
			return

		LOGOUT_URL = self.url + "logout"
		if self.sid:
			headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
			data = {}
			r = requests.post(LOGOUT_URL, verify=False, headers=headers, json=data)
			if self.verbose:
				print(r.text)
			if json.loads(r.text)['message'] == 'OK':
				self.sid = ''
				return True
		return False

	def get_group(self, uid, name=''):
		"""
		The get group functions gets a uid or name and returns a Group object
		depicting the specified group

		Args:
			uid(string) - a specific group obj uid
			name(string) - a specific group obj name
		Returns:
			group(Group) - an obj describing a CP group
		"""
		if not uid and not name:
			raise Exception('tried to call "get_host" func with name AND uid only 1 is needed')
		if not self.sid:
			raise NoSessionException()

		GET_GROUP_URL = self.url + 'show-group'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		if uid:
			data = {'uid': uid, 'details-level': 'full'}
		elif name:
			data = {'name': name, 'details-level': 'full'}

		r = requests.post(GET_GROUP_URL, verify=False, headers=headers, json=data, timeout=5)

		if self.verbose:
			print(r.text)
		try:
			json_obj = json.loads(r.text)
			name = json_obj['name']
			uid = json_obj['uid']
			json_members = json_obj['members']
			members = []
			for json_member in json_members:
				obj_type = json_member['type']
				obj_uid = json_member['uid']
				obj_name = json_member['name']
				if obj_type == TYPE_HOST:
					ip_address = json_member['ipv4-address']
					obj = Host(obj_name, ip_address, obj_uid)
				elif obj_type == TYPE_NETWORK:
					obj = self.get_network(obj_uid)
				elif obj_type == TYPE_GROUP:
					group = self.get_group(obj_uid)
					try:
						obj = group.members
					except AttributeError:
						print(str(group))
				elif obj_type == TYPE_ADDRESS_RANGE:
					obj = self.get_address_range(obj_uid)
				elif obj_type == TYPE_GW_CLUSTER:
					obj = self.get_gateway_cluster(obj_uid)
				elif obj_type == TYPE_GW_CLUSTER_MEMBER:
					obj = self.get_gateway_cluster_member(obj_uid)
				else:
					try:
						obj = self.get_cp_unknown_obj(obj_uid)
					except:
						raise Exception("An unknown obj type was found - {} - {}".format(obj_type, obj_uid))

				if type(obj) is list:
					members += obj
				else:
					members.append(obj)

			# Needs to make sure that only one ICMP is recorded if at all

			return Group(name, members, uid)
		except KeyError:
			return ""

	def get_service(self, uid, service_type):
		"""
		The get service functions gets a uid with service type 
		and returns a Service object.
		Service type can be rpc,tcp,udp

		Args:
			uid(string) - a specific service obj uid
			service_type(string) - a service type !!!all of them are constants at the top of the file!!!
		Returns:
			group(Group) - an obj describing a CP group
		"""

		# Checks if the function params are valid
		if not uid or not service_type:
			raise Exception('tried to call "get_service" func without uid or service_type')
		if not self.sid:
			raise NoSessionException()

		# Use specific URLS for different api calls according to the service type
		if service_type == SERVICE_TCP:
			GET_SERVICE_URL = self.url + 'show-service-tcp'
		elif service_type == SERVICE_UDP:
			GET_SERVICE_URL = self.url + 'show-service-udp'
		elif service_type == SERVICE_DCE_RPC:
			GET_SERVICE_URL = self.url + 'show-service-dce-rpc'
		elif service_type == SERVICE_ICMP:
			return Service("ICMP", ['None'], SERVICE_ICMP, uid)
		elif service_type == SERVICE_OTHER:
			GET_SERVICE_URL = self.url + 'show-service-other'
		elif service_type == TYPE_ANY:
			return Any()
		else:
			raise Exception("Tried to call get_service func with an unknown type : " + service_type)

		# Regular API headers and data
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'uid': uid, 'details-level': 'standard'}

		r = requests.post(GET_SERVICE_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			# Parse the json response
			json_obj = json.loads(r.text)

			# Gets the service base info
			uid = json_obj['uid']
			name = json_obj['name']
			service_type = json_obj['type']

			# DCE_RPC Services dont have a port number
			if service_type == SERVICE_DCE_RPC:
				return Service(name, service_type, uid)
			# Services of the OTHER type use ip protocol instead of regular ports
			if service_type == SERVICE_OTHER:
				ip_port = json_obj['ip-protocol']
				return Service(name, service_type, uid)
			# Ports attr can be either [0] or [0 - 1000] 
			# so I index it accordingly into the class
			if '-' in json_obj['port']:
				start_range = int(json_obj['port'].split('-')[0])
				end_range = int(json_obj['port'].split('-')[1])
				ports = range(start_range, end_range + 1)
			else:
				ports = [int(json_obj['port'])]

			# Returns the service obj we instansified (Regular TCP/UDP)
			return Service(name, service_type, uid, ports=ports)
		except KeyError:
			return ""

	def get_service_group(self, uid):
		"""
		this function returns a group object by supplying a uid
		Args:
			uid(string) - uid of an object
		Returns:
			service-group(Group) - a service group object
		"""
		GET_SERVICE_GROUP_URL = self.url + 'show-service-group'
		# Checks if the function params are valid
		if not uid:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()

		# Regular API headers and data
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'uid': uid, 'details-level': 'standard'}

		r = requests.post(GET_SERVICE_GROUP_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			json_obj = json.loads(r.text)
			name = json_obj['name']
			uid = json_obj['uid']
			json_members = json_obj['members']
			members = []
			for json_member in json_members:
				obj_service_type = json_member['type']
				obj_uid = json_member['uid']
				obj_name = json_member['name']
				if obj_service_type == SERVICE_GROUP:
					members += self.get_service_group(obj_uid).members
				else:
					members.append(self.get_service(obj_uid, obj_service_type))

			return Group(name, members, uid)
		except KeyError:
			return ""

	def get_host(self, uid, name=''):
		"""
		this function returns host object by supplying a uid
		Args or name:
			uid(string) - uid of an object
		Returns:
			name your host or uid object in management
		"""
		if not uid and not name:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()

		GET_HOST_URL = self.url + 'show-host'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		# takes either a name or a uid

		if uid:
			data = {'uid': uid, 'details-level': 'standard'}
		elif name:
			data = {'name': name, 'details-level': 'standard'}

		r = requests.post(GET_HOST_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			data = json.loads(r.text)
			return Host(data['name'], data['ipv4-address'], uid)
		except KeyError:
			return ""

	def get_hosts(self, limit=50, offset=0):
		"""
		get the specified limit of hosts from the CMA
		Args:
			limit(int)(default - 50) - 
		"""

		if not self.sid:
			raise NoSessionException()

		if limit > self.MAX_QUERY_LIMIT:
			print("[x] Querys from the CMA cannot exceed 500 objs at a time")
			return

		GET_HOSTS_URL = self.url + 'show-hosts'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'limit': limit, 'offset': offset, 'details-level': 'full'}
		r = requests.post(GET_HOSTS_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			return json.loads(r.text)['objects']
		except KeyError:
			return ""

	def get_hosts_total(self):
		"""
		gets the total number of hosts in the CMA
		Args:
			None
		Returns:
			host_count(int) - count of the total hosts
		"""

		if not self.sid:
			raise NoSessionException()

		GET_HOSTS_URL = self.url + 'show-hosts'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {}
		r = requests.post(GET_HOSTS_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			return json.loads(r.text)['total']
		except KeyError:
			return ""

	def get_networks(self, limit=50):
		"""
		get the specified amount of networks from the CMA
		Args:
			limit(int)(default - 50) - the amount of networks to get
		Returns:
			networks(array) - array of network objects
		"""
		if not self.sid:
			raise NoSessionException()

		GET_NETWORKS_URL = self.url + 'show-networks'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'limit': limit, 'details-level': 'uid'}
		r = requests.post(GET_NETWORKS_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			return json.loads(r.text)['objects']
		except KeyError:
			return ""

	def get_network(self, uid, name=''):
		"""
		get a network object from the CMA using a uid or name
		Args:
			uid(string) - object uid
			name(string)(default - '') - object name
		Returns:
			network(Network) - a network object
		"""
		if not self.sid:
			raise NoSessionException()

		GET_NETWORK_URL = self.url + 'show-network'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'uid': uid}
		r = requests.post(GET_NETWORK_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			json_obj = json.loads(r.text)
			cp_net_obj = Network(json_obj['name'], json_obj['subnet4'], json_obj['subnet-mask'], json_obj['uid'])
			return cp_net_obj
		except KeyError:
			return ""

	def get_address_range(self, uid):
		"""
		a function to get a address range obj using a uid
		Args:
			uid(string) - obj uid
		Returns:
			address_range(AddressRange) - address range object
		"""
		if not self.sid:
			raise NoSessionException()
		if not uid:
			raise NoIdentifierException()

		GET_ADDRESS_RANGE_URL = self.url + "show-address-range"
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'uid': uid}

		r = requests.post(GET_ADDRESS_RANGE_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			json_obj = json.loads(r.text)
			name = json_obj['name']
			uid = json_obj['uid']
			ipv4_address_start = json_obj['ipv4-address-first']
			ipv4_address_end = json_obj['ipv4-address-last']
			return AddressRange(name, ipv4_address_start, ipv4_address_end, uid)
		except KeyError:
			return ''

	def get_gateway_cluster(self, uid):
		"""
		a function to get a gateway cluster obj using a uid
		Args:
			uid(string) - obj uid
		Returns:
			cluster_obj(Host) - cluster object
		"""
		if not uid:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()

		json_obj = self.__get_cp_object_json__(uid)
		try:
			return Host(json_obj['name'], json_obj['ipv4-address'], json_obj['uid'])
		except KeyError:
			return ''

	def get_gateway_cluster_member(self, uid):
		"""
		a function to get gateway cluster members specific objects using a uid
		Args:
			uid(string) - a uid
		Returns:
			cluster_member_obj(Host) - a cluster member host obj
		"""
		if not uid:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()
		json_obj = self.__get_cp_object_json__(uid)
		try:
			return Host(json_obj['name'], json_obj['ipv4-address'], json_obj['uid'])
		except KeyError:
			return ''

	def get_gateways(self, specific_members=False):
		"""
		a function to get all the gateways objects from the CMA
		Args:
			specific_members(bool)(default - false) - param to specify if you want specific members or
													  or clusters
		Returns:
			gateways(array) - an array of gateways objects
		"""

		if not self.sid:
			raise NoSessionException()

		# gets all the firewalls from the CMA server, can specify if you want clusters or specific members
		GET_OBJECT_URL = self.url + "show-gateways-and-servers"
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {}
		r = requests.post(GET_OBJECT_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			gateways = []
			for gateway_obj in json.loads(r.text)['objects']:
				json_gw_obj = self.__get_cp_object_json__(gateway_obj['uid'], full_details=True)['object']
				gateways.append(
					Gateway(json_gw_obj['name'], json_gw_obj['ipv4-address'], json_gw_obj['uid'], json_gw_obj['type']))
			gateways = filter(lambda obj: 'CMA' not in obj.gw_type.upper(), gateways)
			gateways = filter(lambda obj: 'LOGS' not in obj.gw_type.upper(), gateways)
			if specific_members:
				gateways = filter(lambda obj: obj.gw_type == TYPE_GW_CLUSTER_MEMBER, gateways)
			else:
				gateways = filter(lambda obj: obj.gw_type == TYPE_GW_CLUSTER, gateways)
		except KeyError:
			return ''
		return gateways

	def __get_cp_object_json__(self, uid, full_details=False):
		"""
		a private function that gets json data about an object using his uid.
		its used to get data from unknown object types.
		Args:
			uid(string) - uid of the obj
			full_detials(bool) - decides if the json will contain full details or partial
		Returns:
			json_obj(JSONObj) - returns a json object
		"""
		if not uid:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()

		GET_OBJECT_URL = self.url + "show-object"
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'uid': uid}
		if full_details:
			data['details-level'] = 'full'
		r = requests.post(GET_OBJECT_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			return json.loads(r.text)
		except KeyError:
			return ''

	def get_cp_unknown_obj(self, uid):
		"""
		this funtion takes a uid of an obj and returns bare bones data obj about it
		(!!! should use specific object type get methods instead of this at they 
		are most of the times more specific !!!)
		Args:
			uid(string) - the obj uid
		Returns:
			data_obj(Host) - the data obj (its host because its the most common model of data)
		Extra info:
			in a case the type of the obj is different from
			regular cases (host,network,group etc..) than 
			as a fallback mechanisem the api tried to get
			the data of the obj with the get-obj call to the 
			api, this can in turn cause problems but at least
			it gets some data instead of killing the process
		"""
		if not uid:
			raise NoIdentifierException()
		if not self.sid:
			raise NoSessionException()

		json_obj = self.__get_cp_object_json__(uid)
		try:
			host = Host(json_obj['name'], json_obj['ipv4-address'], json_obj['uid'])
			print("Successfully parsed unknown type obj")
			return host
		except KeyError:
			return ''

	def get_rules_count(self, rulebase="Network"):
		"""
		this function returns the number of rules in the specified rulebase
		Args:
			rulebase(default - "Network") - optional param to specify the rules base to
											take data from
		Returns:
			rule_count(int) - the count of all the rules in the rulebase
		"""
		if not self.sid:
			raise NoSessionException()

		GET_RULEBASE_URL = self.url + "show-access-rulebase"
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'name': rulebase, 'limit': 1, 'offset': 0}
		r = requests.post(GET_RULEBASE_URL, verify=False, headers=headers, json=data)
		if self.verbose:
			print(r.text)
		try:
			return json.loads(r.text)['total']
		except KeyError:
			return ''

	def get_rule(self, rule_number, layer="Network"):
		"""
		this function takes a rule number and returns a rule obj
		Args:
			rule_number(int) - the specified rule number
			layer(string)(default - "Network") - optional param to specify a rule layer
		Returns:
			rule(Rule) - rule obj
		"""
		if not self.sid:
			raise NoSessionException()

		GET_RULE_URL = self.url + 'show-access-rule'
		headers = {'X-chkp-sid': self.sid, 'Content-type': 'application/json'}
		data = {'rule-number': rule_number, 'layer': layer}

		r = requests.post(GET_RULE_URL, verify=False, headers=headers, json=data)

		if self.verbose:
			print(r.text)
		try:
			json_obj = json.loads(r.text)
			enabled = json_obj['enabled']

			try:
				name = json_obj['name']
			except KeyError:
				name = 'Not Defined'

			# Init srcs array 
			sources = []
			for src_obj in json_obj['source']:
				src_type = src_obj['type']
				src_uid = src_obj['uid']
				if src_type == TYPE_HOST:
					obj = self.get_host(src_uid)
				elif src_type == TYPE_NETWORK:
					obj = self.get_network(src_uid)
				elif src_type == TYPE_GROUP:
					obj = self.get_group(src_uid)
				elif src_type == TYPE_ADDRESS_RANGE:
					obj = self.get_address_range(src_uid)
				elif src_type == TYPE_ANY:
					obj = Any()
				else:
					try:
						obj = self.get_cp_unknown_obj(src_uid)
					except:
						raise Exception("Tried to detect src type but failed : {} - {}".format(src_type, src_uid))
				sources.append(obj)

			# Init destinations array
			destinations = []

			for dst_obj in json_obj['destination']:
				dst_type = dst_obj['type']
				dst_uid = dst_obj['uid']
				if dst_type == TYPE_HOST:
					obj = self.get_host(dst_uid)
				elif dst_type == TYPE_NETWORK:
					obj = self.get_network(dst_uid)
				elif dst_type == TYPE_GROUP:
					obj = self.get_group(dst_uid)
				elif dst_type == TYPE_ADDRESS_RANGE:
					obj = self.get_address_range(dst_uid)
				elif dst_type == TYPE_ANY:
					obj = Any()
				else:
					try:
						obj = self.get_cp_unknown_obj(dst_uid)
					except:
						raise Exception("Tried to detect dst type but failed : {} - {}".format(dst_type, dst_uid))

				destinations.append(obj)

			tracked = json_obj['track']['name']
			creation_time_long = json_obj['meta-info']['creation-time']['posix']

			action = json_obj['action']['name']

			# Services
			services = []
			for service_obj in json_obj['service']:
				service_type = service_obj['type']
				service_uid = service_obj['name']
				if service_type == SERVICE_GROUP:
					services += self.get_service_group(service_uid).members
				else:
					services.append(self.get_service(service_uid, service_type))

			rule = Rule(rule_number, enabled, name, sources, destinations, tracked, creation_time_long, services,
			            action)
			return rule
		except KeyError:
			return ""

	def get_rules(self, limit=50, offset=0, layer="Network"):
		"""
		Get rules function gets an entry limit and returns an array of rules.
		this func has more specific options for getting rules, you can specify
		on offset to start with, moreover you can give a specific layer of rules 
		to get the rules from
		Args:
			limit(int)(default - 50) - rule limit (the number of rules to return)
			offset(int)(default - 0) - the rule number offset(where to start from)
			layer(string)(default - "Network") - the layer from which to take the rules
		Returns:
			rules(array) - returns an array of Rule objects
		"""
		ruleset = []
		currant_index = 0
		tasks_queue = Queue.Queue()
		size = limit + offset
		for index in range(1 + offset, size + 1):
			tasks_queue.put({'index': currant_index, 'rule-number': index})
			currant_index += 1
		threads = []
		thread_count = 5

		print('[x] Starting Work \n')
		for index in range(thread_count):
			thread = self.RuleThread(self, tasks_queue, ruleset)
			thread.start()
			threads.append(thread)

		time.sleep(2)
		for index in range(thread_count):
			threads[index].join()

		return ruleset

	def __sid_check__(self):
		# Checks if there is a valid SID, if not prints a msg and returns false 
		if not self.sid:
			print("Invalid SID, have you logged in yet ?")
			return False
		return True

	def __str__(self):
		return "Status : {}\nLogin Time : {}\nSID : {}".format("Alive" if self.sid else "Dead", self.login_time)

	class RuleThread(threading.Thread):
		def __init__(self, conn, queue, ruleset):
			threading.Thread.__init__(self)
			self.conn = conn
			self.queue = queue
			self.ruleset = ruleset
			self.timeout_counter = 0

		def run(self):
			# Runs while the queue has data
			if self.queue.empty():
				print("queue empty")
			while not self.queue.empty():
				self.timeout_counter = 0
				data = self.queue.get()
				rule_number = data['rule-number']
				index = data['index']
				try:
					rule = self.get_rule(rule_number)
				except RuleGetError:
					rule = 'Rule {} failed to fetch from CMA'.format(rule_number)
				print("[x] Finished Getting Rule {}\n".format(rule_number))
				self.ruleset.insert(index, rule)
				time.sleep(1)

		def get_rule(self, rule_number):
			# Made to be a failsafe measure for getting rules
			try:
				rule = self.conn.get_rule(rule_number)
				self.timeout_counter = 0
				return rule
			except:
				if self.timeout_counter > 3:
					raise RuleGetError()
				else:
					time.sleep(1)
					self.timeout_counter += 1
					self.get_rule(rule_number)


class Analyzer:
	"""
	This class handles all the rule analysis area.
	Analyzing if something would pass the given ruleset
	can be done using a couple steps
	1) init the class with a given ruleset (array of rules)
	2)set source ip (setSource func), set destination ip (setDestination func)
	  set service (setService func)
	3) call the analyze func
	"""

	def __init__(self, rule_set):
		self.rule_set = rule_set  # takes a rule set

	def setSource(self, ip_address):
		self.source = ip_address

	def setDestination(self, ip_address):
		self.destination = ip_address

	def setService(self, service_type, port=-1, ip_protocol=-1):
		"""
		sets the call service
		Input:
		**ENUM is the given values as constants at the top of the class**
			port(int - optional)- port numeber
			ip_protocol(ENUM) - TCP or UDP
			service_type(ENUM) - service type
		"""
		self.port = port  # Relevent to TCP/UDP Services
		self.service_type = service_type  # Relevent to all services
		self.ip_protocol = ip_protocol  # Relevent only to OTHER type services

	def __checkports__(self, services):
		if services:
			for service in services:
				# If the service is set to ANY accept anything
				if isinstance(service, Any):
					return True
				# Checks if the service is actually of Service class
				elif isinstance(service, Service):
					# Checks if the service type is the same (TCP,UDP,RPC, etc...)
					# If the service is ICMP return True as it doesnt use any specific port (dont kill me)
					if service.service_type == self.service_type:
						# Checks if the port specificed is in the port list of the service
						if service.service_type == SERVICE_ICMP:
							return True
						if service.service_type == SERVICE_DCE_RPC:
							return True
						if service.service_type == SERVICE_OTHER and service.ip_protocol == self.ip_protocol:
							return True
						return filter(lambda port: str(self.port) == str(port), service.ports)
		return False

	def __checksources__(self, sources):
		if sources:
			for source in sources:
				# If the service is set to ANY accept anything
				if isinstance(source, Any):
					return True
				# Checks the source address class type (Host,Group,Address Range,Network)
				elif isinstance(source, Host):
					return self.source == source.ip
				elif isinstance(source, Group):
					return self.source in source.members
				elif isinstance(source, Network):
					# using the 'ipaddress' lib i check if the source address is in the net id
					network = ipaddress.ip_network(u'{}/{}'.format(source.net_id, source.getMaskBytes()))
					address = ipaddress.ip_address(u'{}'.format(self.source))
					return address in network
				elif isinstance(source, AddressRange):
					# using the 'ipaddress' lib I find if the ip is in the range of addresses
					start = ipaddress.ip_address(source.ipv4_address_start)
					end = ipaddress.ip_address(source.ipv4_address_end)
					# iterating over all the possible IP addresses
					address_range = []
					while start <= end:
						address_range.append(str(start))
						start += 1
					return source in address_range
		return False

	def __checkdests__(self, destinations, start_address, end_address):
		if destinations:
			for destination in destinations:
				# If the service is set to ANY accept anything
				if isinstance(destination, Any):
					return True
				# Checks the source address class type (Host,Group,Address Range,Network)
				elif isinstance(destination, Host):
					return self.destination == destination.ip
				elif isinstance(destination, Group):
					return self.destination in destination.members
				elif isinstance(destination, Network):
					# using the 'ipaddress' lib i check if the source address is in the net id
					network = ipaddress.ip_network(u'{}/{}'.format(destination.net_id, destination.getMaskBytes()))
					address = ipaddress.ip_address(u'{}'.format(self.source))
					return address in network
				elif isinstance(destination, AddressRange, start_address, end_address):
					# using the 'ipaddress' lib I find if the ip is in the range of addresses
					start = ipaddress.ip_address(start_address)
					end = ipaddress.ip_address(end_address)
					# iterating over all the possible IP addresses
					address_range = []
					while start <= end:
						address_range.append(str(start))
						start += 1
					return destination in address_range
		return False

	def analyze(self):
		"""
		analyzes a given ruleset and returns if the given call will pass 
		through it or will it be dropped

		Returns:
			will_pass(bool) - will the call pass the rule or not
		"""
		try:
			if not self.rule_set or not self.source or not self.destination or not self.port or not self.service_type:
				raise Exception("""Tried to call analyze without supplying 
					the right params (rule set, source, destination, port, service type""")
			for rule in self.rule_set:
				if rule.enabled:
					if self.__checkports__(rule.services) \
							and self.__checksources__(rule.sources) \
							and self.__checkdests__(rule.destinations):
						# print 'Rule Matched :\n' + str(rule)
						if rule.action == ACTION_ACCEPT:
							return True
						elif rule.action == ACTION_DROP:
							return False
		except AttributeError:
			return False
		# If we passed all the rules and nothing was
		# explicitly permited then drop the packet
		return False
