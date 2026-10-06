module Dnsruby
  class ClientSubnetResolver
    DEFAULT_SOURCE_PREFIXES = {
      RR::OPT::IPV4_ADDRESS_FAMILY => 24,
      RR::OPT::IPV6_ADDRESS_FAMILY => 56
    }.freeze

    def initialize(source_prefixes: nil, transport: nil, resolver: nil, resolver_options: nil,
                   clock: nil, index: nil, payloadsize: Resolver::DefaultUDPSize)
      @source_prefixes = DEFAULT_SOURCE_PREFIXES.merge(source_prefixes || {})
      @resolver = resolver
      @resolver_options = resolver_options || {}
      @transport = transport
      @index = index || ECSAnswerIndex.new(clock: clock)
      @payloadsize = payloadsize
    end

    def query(name, type = Types.A, klass = Classes.IN, client_address:)
      request_subnet = request_subnet_for(client_address)
      question = Question.new(name, type, klass)
      message = Message.new
      message.header.rd = true
      message.do_caching = false
      message.do_validation = false
      message.add_question(question)
      opt = RR::OPT.new(@payloadsize)
      message.add_additional(opt)
      opt.set_client_subnet(request_subnet)

      cached = @index.find(question, request_subnet)
      if cached
        cached.header.id = message.header.id
        return cached
      end

      response = transport.call(message)
      begin
        response_subnet = response.get_opt&.client_subnet
      rescue DecodeError => error
        raise ECSAssociationError.new(error.message)
      end
      unless response_subnet&.valid_response_to?(request_subnet)
        raise ECSAssociationError.new("response EDNS client subnet does not match the request")
      end

      @index.add(message, response)
      response
    end

    private

    def transport
      @transport ||= lambda do |message|
        @resolver ||= Resolver.new(@resolver_options)
        @resolver.send_message(message)
      end
    end

    def request_subnet_for(client_address)
      address = IPAddr.new(client_address)
      family = address.ipv4? ? RR::OPT::IPV4_ADDRESS_FAMILY : RR::OPT::IPV6_ADDRESS_FAMILY
      source_prefix = @source_prefixes.fetch(family)
      ClientSubnet.new(address, source_prefix, 0)
    end
  end
end
