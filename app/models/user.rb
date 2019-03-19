class User < ApplicationRecord
  has_many :microposts, dependent: :destroy
  validates :name, presence: true, length: {maximum: 50}
  attr_accessor :remember_token, :activation_token, :reset_token
  before_save :downcase_email
  before_create :create_activation_digest


  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: {maximum: 255},
            format: {with: VALID_EMAIL_REGEX},
            uniqueness: {case_sensitive: false}
  has_secure_password
  validates :password, presence: true, length: {minimum: 6}, allow_nil: true

  # 渡された文字列のハッシュ値を返す
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
               BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  # ランダムなトークンを返すメソッド
  def User.new_token
    SecureRandom.urlsafe_base64
  end

  # DBにremember_digestの保存
  def remember
    self.remember_token = User.new_token
    self.update_attribute(:remember_digest, User.digest(remember_token))
  end

  # DBにremember_digestを破棄する
  def forget
    self.update_attribute(:remember_digest, nil)
  end

  # cookieのトークンとダイジェストが一致したら、trueを返す
  # attributeを使って、汎用化した
  def authenticated?(attribute, token)
    digest = self.send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  # アカウントを有効化する
  def activate
    update_attribute(:activated, true)
    update_attribute(:activated_at, Time.zone.now)
  end

  # 有効用のメールを送信する
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  # パスワード再設定の属性を設定する
  def create_reset_digest
    self.reset_token = User.new_token
    update_attribute(:reset_digest, User.digest(reset_token))
    update_attribute(:reset_send_at, Time.zone.now)
  end

  # パスワード再設定のメールを送信する
  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end

  # パスワードの期限が切れてる場合はtrueを返す。
  def password_reset_expired?
    reset_send_at < 2.hours.ago
  end

  def feed
    Micropost.where("user_id = ?", self.id)
  end

  private
    # emailを全て小文字にする
    def downcase_email
      self.email = self.email.downcase
    end

    # カラムにactivation_tokenをハッシュ化したものを入れる
    def create_activation_digest
      self.activation_token = User.new_token
      # ハッシュ化する
      self.activation_digest = User.digest(self.activation_token)
    end

end
