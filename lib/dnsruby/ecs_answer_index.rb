require 'ipaddr'

module Dnsruby
  class ECSAssociationError < ResolvError
  end

  class ECSAnswerIndex
    Entry = Struct.new(:data, :client_subnet, :scope_key)

    def initialize(clock: nil, max_size: 16 * 1024)
      @clock = clock
      @max_size = max_size
      @entries = {}
      @mutex = Mutex.new
    end

    def clear
      @mutex.synchronize { @entries.clear }
    end

    def length
      @mutex.synchronize { @entries.length }
    end

    def add(query, response)
      request = client_subnet_from(query)
      begin
        answer = client_subnet_from(response)
      rescue DecodeError => error
        raise ECSAssociationError.new(error.message)
      end
      unless request && request.scope_prefix == 0 && answer&.valid_response_to?(request) &&
          response.rcode == RCode::NOERROR && response.header.ancount > 0
        raise ECSAssociationError.new("response EDNS client subnet does not match the request")
      end

      question = response.question[0] || query.question[0]
      data = Cache::CacheData.new(response, @clock)
      scope_key = scope_key(answer)
      entry = Entry.new(data, answer, scope_key)
      @mutex.synchronize do
        @entries[[question_key(question), scope_key]] = entry
        @entries.shift while @entries.size > @max_size
      end
    end

    def find(question, client_subnet)
      client_subnet = ClientSubnet.create(client_subnet)
      base_key = question_key(question)
      @mutex.synchronize do
        expired_keys = []
        match = nil

        @entries.each do |(entry_question_key, _scope_key), entry|
          next unless entry_question_key == base_key
          expired_keys << [entry_question_key, entry.scope_key] unless fresh?(entry)
          next unless fresh?(entry)
          next unless entry.client_subnet.covers?(client_subnet)
          match = entry if match.nil? || entry.client_subnet.scope_prefix > match.client_subnet.scope_prefix
        end

        expired_keys.each { |key| @entries.delete(key) }
        match&.data&.message
      end
    end

    private

    def client_subnet_from(message)
      message.get_opt&.client_subnet
    end

    def question_key(question)
      qname = question.qname.dup
      qname.absolute = true
      [qname.inspect.downcase, Classes.new(question.qclass).code, Types.new(question.qtype).code]
    end

    def scope_key(subnet)
      [subnet.family, subnet.scope_prefix, subnet.scope_address.to_s]
    end

    def fresh?(entry)
      entry.data.expiration > clock_now.to_i
    end

    def clock_now
      return Time.now unless @clock
      @clock.respond_to?(:now) ? @clock.now : @clock.call
    end
  end
end
