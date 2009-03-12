require "rubygems"
require "net/ldap"

class AuthenticateLdap
  attr_accessor :username, :password, :ldaphost, :domain, :tld

  #create a constructor which takes all relevant parameters and saves them
  #to their corresponding attributes
  def initialize(username, password, ou, ldaphost, domain, tld)
    @username = username
    @password = password
    @ou = ou
    @ldaphost = ldaphost
    @domain = domain
    @tld = tld
    @base = "dc=#{@domain},dc=#{@tld}"
    @dn = "uid=#{@username},ou=#{@ou},dc=#{@domain},dc=#{@tld}"
  end

  #validates the user against OpenLDAP and returns a boolean value stating
  #whether the user was successfully authenticated or not.
  def valid_user?
    @ldap = Net::LDAP.new(:base => @base,
      :host => @ldaphost,
      :auth => {:username => @dn,
        :password => @password,
      :method => :simple})
    #return a boolean indicating whether authentication was successful or not
    return @ldap.bind
  end

  def valid_user_and_in_group?(group_cn, group_ou)
    group_dn = "cn=#{group_cn},ou=#{group_ou},#{@base}"
    #authenticate user, only if that succeeds will be checked for membership
    #within the specified group cn
    if valid_user?
      f = Net::LDAP::Filter.eq("uniqueMember",@dn)
      results = @ldap.search(:filter=>f, :base=>@base)
      group_names = results.first[:dn]
      return group_names.any?{|name| name.include? "cn=#{group_cn},ou=#{group_ou},"}
    end
    #the user membership in the specified group could not be verified
    return false
  end
end