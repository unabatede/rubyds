require "rubygems"
require "net/ldap"

#provides authentication services for Active Directory Services
class AuthenticateAds
  attr_accessor :username, :password, :adshost, :domain, :tld

  #create a constructor which takes all relevant parameters and saves them
  #to their corresponding attributes
  def initialize(username, password, adshost, domain, tld)
    @username = username
    @password = password
    @adshost = adshost
    @domain = domain
    @tld = tld
  end

  #validates the user against Active Directory and returns a boolean value stating
  #whether the user was successfully authenticated or not.
  def valid_user?
    #create a new LDAP object using the ruby-net-ldap library
    @ldap = Net::LDAP.new(:base => "dc=#{@domain},dc=#{@tld}",
      :host => @adshost,
      :auth => {:username => "#{@username}@#{@domain}.#{@tld}",
        :password => @password,
        :method => :simple})
    #return a boolean indicating whether authentication was successful or not
    return @ldap.bind
  end

  def valid_user_and_in_group?(group_cn)
    #authenticate user, only if that succeeds will be checked for membership
    #within the specified group cn
    if valid_user?
      results = @ldap.search(:filter=>"sAMAccountName=#{@username}")
      group_names = results.first[:memberof]
      return group_names.any?{|name| name.include? "CN=#{group_cn},"}
    end
    #the user membership in the specified group could not be verified
    return false
  end
end

